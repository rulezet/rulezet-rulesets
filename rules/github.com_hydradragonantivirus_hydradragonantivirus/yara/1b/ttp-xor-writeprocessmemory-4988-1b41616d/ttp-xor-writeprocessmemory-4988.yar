rule TTP_XOR_WriteProcessMemory_4988 {
  strings:
    $key_4988 = { 1e fa [2] 2c d8 [2] 2a ed [2] 04 ed [2] 3b f1 }

  condition:
    any of them
}