rule TTP_XOR_WriteProcessMemory_fea4 {
  strings:
    $key_fea4 = { a9 d6 [2] 9b f4 [2] 9d c1 [2] b3 c1 [2] 8c dd }

  condition:
    any of them
}