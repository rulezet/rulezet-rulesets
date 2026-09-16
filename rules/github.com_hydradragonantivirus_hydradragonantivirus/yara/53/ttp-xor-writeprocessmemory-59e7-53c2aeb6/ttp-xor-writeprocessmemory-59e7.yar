rule TTP_XOR_WriteProcessMemory_59e7 {
  strings:
    $key_59e7 = { 0e 95 [2] 3c b7 [2] 3a 82 [2] 14 82 [2] 2b 9e }

  condition:
    any of them
}