rule TTP_XOR_WriteProcessMemory_5d87 {
  strings:
    $key_5d87 = { 0a f5 [2] 38 d7 [2] 3e e2 [2] 10 e2 [2] 2f fe }

  condition:
    any of them
}