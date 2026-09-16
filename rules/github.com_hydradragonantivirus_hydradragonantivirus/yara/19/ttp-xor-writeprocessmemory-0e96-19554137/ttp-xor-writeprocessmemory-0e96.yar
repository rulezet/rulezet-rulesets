rule TTP_XOR_WriteProcessMemory_0e96 {
  strings:
    $key_0e96 = { 59 e4 [2] 6b c6 [2] 6d f3 [2] 43 f3 [2] 7c ef }

  condition:
    any of them
}