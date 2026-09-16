rule TTP_XOR_WriteProcessMemory_1988 {
  strings:
    $key_1988 = { 4e fa [2] 7c d8 [2] 7a ed [2] 54 ed [2] 6b f1 }

  condition:
    any of them
}