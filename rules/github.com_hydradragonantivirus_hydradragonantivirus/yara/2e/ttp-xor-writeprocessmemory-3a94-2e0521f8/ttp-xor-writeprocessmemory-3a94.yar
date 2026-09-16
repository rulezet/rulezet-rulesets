rule TTP_XOR_WriteProcessMemory_3a94 {
  strings:
    $key_3a94 = { 6d e6 [2] 5f c4 [2] 59 f1 [2] 77 f1 [2] 48 ed }

  condition:
    any of them
}