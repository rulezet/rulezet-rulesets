rule TTP_XOR_WriteProcessMemory_76d7 {
  strings:
    $key_76d7 = { 21 a5 [2] 13 87 [2] 15 b2 [2] 3b b2 [2] 04 ae }

  condition:
    any of them
}