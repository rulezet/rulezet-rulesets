rule TTP_XOR_WriteProcessMemory_59e2 {
  strings:
    $key_59e2 = { 0e 90 [2] 3c b2 [2] 3a 87 [2] 14 87 [2] 2b 9b }

  condition:
    any of them
}