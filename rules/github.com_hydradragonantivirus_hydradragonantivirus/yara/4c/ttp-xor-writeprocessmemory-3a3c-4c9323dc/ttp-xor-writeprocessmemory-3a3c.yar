rule TTP_XOR_WriteProcessMemory_3a3c {
  strings:
    $key_3a3c = { 6d 4e [2] 5f 6c [2] 59 59 [2] 77 59 [2] 48 45 }

  condition:
    any of them
}