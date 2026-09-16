rule TTP_XOR_WriteProcessMemory_45e6 {
  strings:
    $key_45e6 = { 12 94 [2] 20 b6 [2] 26 83 [2] 08 83 [2] 37 9f }

  condition:
    any of them
}