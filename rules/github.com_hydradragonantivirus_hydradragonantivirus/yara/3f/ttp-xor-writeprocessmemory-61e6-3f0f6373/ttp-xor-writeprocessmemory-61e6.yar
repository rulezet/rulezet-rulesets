rule TTP_XOR_WriteProcessMemory_61e6 {
  strings:
    $key_61e6 = { 36 94 [2] 04 b6 [2] 02 83 [2] 2c 83 [2] 13 9f }

  condition:
    any of them
}