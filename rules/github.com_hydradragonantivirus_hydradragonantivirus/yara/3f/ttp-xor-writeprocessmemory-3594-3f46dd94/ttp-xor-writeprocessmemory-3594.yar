rule TTP_XOR_WriteProcessMemory_3594 {
  strings:
    $key_3594 = { 62 e6 [2] 50 c4 [2] 56 f1 [2] 78 f1 [2] 47 ed }

  condition:
    any of them
}