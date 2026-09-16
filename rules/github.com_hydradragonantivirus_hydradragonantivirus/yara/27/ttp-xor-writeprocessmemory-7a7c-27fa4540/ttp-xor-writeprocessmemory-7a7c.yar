rule TTP_XOR_WriteProcessMemory_7a7c {
  strings:
    $key_7a7c = { 2d 0e [2] 1f 2c [2] 19 19 [2] 37 19 [2] 08 05 }

  condition:
    any of them
}