rule TTP_XOR_WriteProcessMemory_4d87 {
  strings:
    $key_4d87 = { 1a f5 [2] 28 d7 [2] 2e e2 [2] 00 e2 [2] 3f fe }

  condition:
    any of them
}