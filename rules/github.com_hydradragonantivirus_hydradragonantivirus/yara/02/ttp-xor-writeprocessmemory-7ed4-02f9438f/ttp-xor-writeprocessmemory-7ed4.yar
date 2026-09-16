rule TTP_XOR_WriteProcessMemory_7ed4 {
  strings:
    $key_7ed4 = { 29 a6 [2] 1b 84 [2] 1d b1 [2] 33 b1 [2] 0c ad }

  condition:
    any of them
}