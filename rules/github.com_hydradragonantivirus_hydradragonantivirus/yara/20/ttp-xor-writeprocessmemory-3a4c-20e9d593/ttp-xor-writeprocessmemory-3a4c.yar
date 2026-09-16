rule TTP_XOR_WriteProcessMemory_3a4c {
  strings:
    $key_3a4c = { 6d 3e [2] 5f 1c [2] 59 29 [2] 77 29 [2] 48 35 }

  condition:
    any of them
}