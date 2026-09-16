rule TTP_XOR_WriteProcessMemory_4ed3 {
  strings:
    $key_4ed3 = { 19 a1 [2] 2b 83 [2] 2d b6 [2] 03 b6 [2] 3c aa }

  condition:
    any of them
}