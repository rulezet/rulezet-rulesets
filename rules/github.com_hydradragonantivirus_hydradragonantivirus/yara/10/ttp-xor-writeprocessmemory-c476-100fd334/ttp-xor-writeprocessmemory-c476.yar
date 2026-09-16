rule TTP_XOR_WriteProcessMemory_c476 {
  strings:
    $key_c476 = { 93 04 [2] a1 26 [2] a7 13 [2] 89 13 [2] b6 0f }

  condition:
    any of them
}