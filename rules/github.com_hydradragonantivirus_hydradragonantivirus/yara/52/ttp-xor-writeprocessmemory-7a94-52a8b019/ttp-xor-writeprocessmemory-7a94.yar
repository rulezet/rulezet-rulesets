rule TTP_XOR_WriteProcessMemory_7a94 {
  strings:
    $key_7a94 = { 2d e6 [2] 1f c4 [2] 19 f1 [2] 37 f1 [2] 08 ed }

  condition:
    any of them
}