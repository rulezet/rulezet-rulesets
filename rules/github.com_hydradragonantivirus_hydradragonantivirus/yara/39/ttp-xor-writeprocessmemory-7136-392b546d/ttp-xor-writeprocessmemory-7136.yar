rule TTP_XOR_WriteProcessMemory_7136 {
  strings:
    $key_7136 = { 26 44 [2] 14 66 [2] 12 53 [2] 3c 53 [2] 03 4f }

  condition:
    any of them
}