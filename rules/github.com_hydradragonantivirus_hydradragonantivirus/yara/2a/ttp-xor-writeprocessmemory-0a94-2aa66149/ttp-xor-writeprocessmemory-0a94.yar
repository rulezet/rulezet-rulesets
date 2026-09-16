rule TTP_XOR_WriteProcessMemory_0a94 {
  strings:
    $key_0a94 = { 5d e6 [2] 6f c4 [2] 69 f1 [2] 47 f1 [2] 78 ed }

  condition:
    any of them
}