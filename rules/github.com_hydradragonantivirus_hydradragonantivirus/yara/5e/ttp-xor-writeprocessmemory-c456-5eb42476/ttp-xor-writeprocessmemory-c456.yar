rule TTP_XOR_WriteProcessMemory_c456 {
  strings:
    $key_c456 = { 93 24 [2] a1 06 [2] a7 33 [2] 89 33 [2] b6 2f }

  condition:
    any of them
}