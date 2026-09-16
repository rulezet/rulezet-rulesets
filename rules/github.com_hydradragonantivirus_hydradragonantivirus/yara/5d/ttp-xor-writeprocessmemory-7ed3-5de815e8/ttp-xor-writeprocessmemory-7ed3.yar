rule TTP_XOR_WriteProcessMemory_7ed3 {
  strings:
    $key_7ed3 = { 29 a1 [2] 1b 83 [2] 1d b6 [2] 33 b6 [2] 0c aa }

  condition:
    any of them
}