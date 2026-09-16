rule TTP_XOR_WriteProcessMemory_76c3 {
  strings:
    $key_76c3 = { 21 b1 [2] 13 93 [2] 15 a6 [2] 3b a6 [2] 04 ba }

  condition:
    any of them
}