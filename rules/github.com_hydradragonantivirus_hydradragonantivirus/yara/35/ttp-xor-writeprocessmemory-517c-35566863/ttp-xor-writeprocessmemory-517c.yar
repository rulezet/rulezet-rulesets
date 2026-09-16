rule TTP_XOR_WriteProcessMemory_517c {
  strings:
    $key_517c = { 06 0e [2] 34 2c [2] 32 19 [2] 1c 19 [2] 23 05 }

  condition:
    any of them
}