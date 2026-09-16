rule TTP_XOR_WriteProcessMemory_1736 {
  strings:
    $key_1736 = { 40 44 [2] 72 66 [2] 74 53 [2] 5a 53 [2] 65 4f }

  condition:
    any of them
}