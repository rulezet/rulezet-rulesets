rule TTP_XOR_WriteProcessMemory_0094 {
  strings:
    $key_0094 = { 57 e6 [2] 65 c4 [2] 63 f1 [2] 4d f1 [2] 72 ed }

  condition:
    any of them
}