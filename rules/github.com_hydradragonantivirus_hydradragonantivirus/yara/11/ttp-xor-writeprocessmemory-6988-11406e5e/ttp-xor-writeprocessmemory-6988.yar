rule TTP_XOR_WriteProcessMemory_6988 {
  strings:
    $key_6988 = { 3e fa [2] 0c d8 [2] 0a ed [2] 24 ed [2] 1b f1 }

  condition:
    any of them
}