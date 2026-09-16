rule TTP_XOR_WriteProcessMemory_0fa3 {
  strings:
    $key_0fa3 = { 58 d1 [2] 6a f3 [2] 6c c6 [2] 42 c6 [2] 7d da }

  condition:
    any of them
}