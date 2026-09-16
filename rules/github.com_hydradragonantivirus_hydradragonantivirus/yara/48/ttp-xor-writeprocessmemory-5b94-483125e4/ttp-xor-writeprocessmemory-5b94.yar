rule TTP_XOR_WriteProcessMemory_5b94 {
  strings:
    $key_5b94 = { 0c e6 [2] 3e c4 [2] 38 f1 [2] 16 f1 [2] 29 ed }

  condition:
    any of them
}