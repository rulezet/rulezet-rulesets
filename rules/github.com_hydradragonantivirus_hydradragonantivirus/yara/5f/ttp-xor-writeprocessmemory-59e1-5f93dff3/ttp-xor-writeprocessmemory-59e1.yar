rule TTP_XOR_WriteProcessMemory_59e1 {
  strings:
    $key_59e1 = { 0e 93 [2] 3c b1 [2] 3a 84 [2] 14 84 [2] 2b 98 }

  condition:
    any of them
}