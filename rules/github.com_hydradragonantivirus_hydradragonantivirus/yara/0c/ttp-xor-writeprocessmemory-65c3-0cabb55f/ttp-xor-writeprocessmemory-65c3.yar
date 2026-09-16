rule TTP_XOR_WriteProcessMemory_65c3 {
  strings:
    $key_65c3 = { 32 b1 [2] 00 93 [2] 06 a6 [2] 28 a6 [2] 17 ba }

  condition:
    any of them
}