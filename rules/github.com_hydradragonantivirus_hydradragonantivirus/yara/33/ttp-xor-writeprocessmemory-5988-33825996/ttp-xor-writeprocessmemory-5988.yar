rule TTP_XOR_WriteProcessMemory_5988 {
  strings:
    $key_5988 = { 0e fa [2] 3c d8 [2] 3a ed [2] 14 ed [2] 2b f1 }

  condition:
    any of them
}