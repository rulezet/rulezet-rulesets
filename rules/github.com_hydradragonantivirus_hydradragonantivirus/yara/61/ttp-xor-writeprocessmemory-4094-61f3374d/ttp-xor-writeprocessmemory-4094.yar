rule TTP_XOR_WriteProcessMemory_4094 {
  strings:
    $key_4094 = { 17 e6 [2] 25 c4 [2] 23 f1 [2] 0d f1 [2] 32 ed }

  condition:
    any of them
}