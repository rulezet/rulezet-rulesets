rule TTP_XOR_WriteProcessMemory_3e96 {
  strings:
    $key_3e96 = { 69 e4 [2] 5b c6 [2] 5d f3 [2] 73 f3 [2] 4c ef }

  condition:
    any of them
}