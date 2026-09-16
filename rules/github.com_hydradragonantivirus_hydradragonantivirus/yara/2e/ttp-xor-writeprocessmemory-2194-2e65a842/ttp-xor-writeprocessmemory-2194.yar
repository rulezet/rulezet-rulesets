rule TTP_XOR_WriteProcessMemory_2194 {
  strings:
    $key_2194 = { 76 e6 [2] 44 c4 [2] 42 f1 [2] 6c f1 [2] 53 ed }

  condition:
    any of them
}