rule TTP_XOR_WriteProcessMemory_2d87 {
  strings:
    $key_2d87 = { 7a f5 [2] 48 d7 [2] 4e e2 [2] 60 e2 [2] 5f fe }

  condition:
    any of them
}