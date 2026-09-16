rule TTP_XOR_WriteProcessMemory_1136 {
  strings:
    $key_1136 = { 46 44 [2] 74 66 [2] 72 53 [2] 5c 53 [2] 63 4f }

  condition:
    any of them
}