rule TTP_XOR_WriteProcessMemory_3094 {
  strings:
    $key_3094 = { 67 e6 [2] 55 c4 [2] 53 f1 [2] 7d f1 [2] 42 ed }

  condition:
    any of them
}