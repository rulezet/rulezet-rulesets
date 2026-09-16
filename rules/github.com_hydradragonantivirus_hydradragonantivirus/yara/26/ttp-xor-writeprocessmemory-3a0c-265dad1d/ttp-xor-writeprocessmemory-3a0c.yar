rule TTP_XOR_WriteProcessMemory_3a0c {
  strings:
    $key_3a0c = { 6d 7e [2] 5f 5c [2] 59 69 [2] 77 69 [2] 48 75 }

  condition:
    any of them
}