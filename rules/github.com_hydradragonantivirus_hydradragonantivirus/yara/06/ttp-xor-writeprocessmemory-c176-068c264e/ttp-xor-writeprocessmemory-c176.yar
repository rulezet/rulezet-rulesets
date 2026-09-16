rule TTP_XOR_WriteProcessMemory_c176 {
  strings:
    $key_c176 = { 96 04 [2] a4 26 [2] a2 13 [2] 8c 13 [2] b3 0f }

  condition:
    any of them
}