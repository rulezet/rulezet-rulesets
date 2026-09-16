rule TTP_XOR_WriteProcessMemory_6e96 {
  strings:
    $key_6e96 = { 39 e4 [2] 0b c6 [2] 0d f3 [2] 23 f3 [2] 1c ef }

  condition:
    any of them
}