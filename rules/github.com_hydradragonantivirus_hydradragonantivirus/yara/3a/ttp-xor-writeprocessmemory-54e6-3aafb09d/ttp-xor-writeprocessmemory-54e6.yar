rule TTP_XOR_WriteProcessMemory_54e6 {
  strings:
    $key_54e6 = { 03 94 [2] 31 b6 [2] 37 83 [2] 19 83 [2] 26 9f }

  condition:
    any of them
}