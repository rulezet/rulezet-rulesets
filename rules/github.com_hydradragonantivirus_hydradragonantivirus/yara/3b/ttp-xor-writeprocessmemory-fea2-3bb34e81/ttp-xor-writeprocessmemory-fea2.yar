rule TTP_XOR_WriteProcessMemory_fea2 {
  strings:
    $key_fea2 = { a9 d0 [2] 9b f2 [2] 9d c7 [2] b3 c7 [2] 8c db }

  condition:
    any of them
}