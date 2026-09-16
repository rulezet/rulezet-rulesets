rule TTP_XOR_WriteProcessMemory_61e4 {
  strings:
    $key_61e4 = { 36 96 [2] 04 b4 [2] 02 81 [2] 2c 81 [2] 13 9d }

  condition:
    any of them
}