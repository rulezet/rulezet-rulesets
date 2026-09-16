rule TTP_XOR_WriteProcessMemory_cc94 {
  strings:
    $key_cc94 = { 9b e6 [2] a9 c4 [2] af f1 [2] 81 f1 [2] be ed }

  condition:
    any of them
}