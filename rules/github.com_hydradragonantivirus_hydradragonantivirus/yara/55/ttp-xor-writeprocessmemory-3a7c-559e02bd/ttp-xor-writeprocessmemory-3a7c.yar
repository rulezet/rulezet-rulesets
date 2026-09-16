rule TTP_XOR_WriteProcessMemory_3a7c {
  strings:
    $key_3a7c = { 6d 0e [2] 5f 2c [2] 59 19 [2] 77 19 [2] 48 05 }

  condition:
    any of them
}