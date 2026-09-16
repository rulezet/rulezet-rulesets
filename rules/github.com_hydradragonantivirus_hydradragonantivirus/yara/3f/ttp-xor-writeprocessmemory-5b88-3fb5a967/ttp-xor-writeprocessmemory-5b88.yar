rule TTP_XOR_WriteProcessMemory_5b88 {
  strings:
    $key_5b88 = { 0c fa [2] 3e d8 [2] 38 ed [2] 16 ed [2] 29 f1 }

  condition:
    any of them
}