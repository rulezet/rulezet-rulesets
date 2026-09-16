rule TTP_XOR_WriteProcessMemory_36f6 {
  strings:
    $key_36f6 = { 61 84 [2] 53 a6 [2] 55 93 [2] 7b 93 [2] 44 8f }

  condition:
    any of them
}