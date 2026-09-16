rule TTP_XOR_WriteProcessMemory_5f7c {
  strings:
    $key_5f7c = { 08 0e [2] 3a 2c [2] 3c 19 [2] 12 19 [2] 2d 05 }

  condition:
    any of them
}