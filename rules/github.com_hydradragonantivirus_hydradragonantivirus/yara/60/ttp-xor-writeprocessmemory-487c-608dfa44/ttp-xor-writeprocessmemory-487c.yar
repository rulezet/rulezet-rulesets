rule TTP_XOR_WriteProcessMemory_487c {
  strings:
    $key_487c = { 1f 0e [2] 2d 2c [2] 2b 19 [2] 05 19 [2] 3a 05 }

  condition:
    any of them
}