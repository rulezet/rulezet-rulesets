rule TTP_XOR_WriteProcessMemory_39b4 {
  strings:
    $key_39b4 = { 6e c6 [2] 5c e4 [2] 5a d1 [2] 74 d1 [2] 4b cd }

  condition:
    any of them
}