rule TTP_XOR_WriteProcessMemory_e67c {
  strings:
    $key_e67c = { b1 0e [2] 83 2c [2] 85 19 [2] ab 19 [2] 94 05 }

  condition:
    any of them
}