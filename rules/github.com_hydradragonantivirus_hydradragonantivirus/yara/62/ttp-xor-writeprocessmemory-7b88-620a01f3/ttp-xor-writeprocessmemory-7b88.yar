rule TTP_XOR_WriteProcessMemory_7b88 {
  strings:
    $key_7b88 = { 2c fa [2] 1e d8 [2] 18 ed [2] 36 ed [2] 09 f1 }

  condition:
    any of them
}