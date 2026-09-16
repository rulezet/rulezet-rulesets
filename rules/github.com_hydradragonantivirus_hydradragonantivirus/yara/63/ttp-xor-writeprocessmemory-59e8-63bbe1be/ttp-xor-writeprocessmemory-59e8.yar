rule TTP_XOR_WriteProcessMemory_59e8 {
  strings:
    $key_59e8 = { 0e 9a [2] 3c b8 [2] 3a 8d [2] 14 8d [2] 2b 91 }

  condition:
    any of them
}