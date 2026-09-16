rule TTP_XOR_WriteProcessMemory_748c {
  strings:
    $key_748c = { 23 fe [2] 11 dc [2] 17 e9 [2] 39 e9 [2] 06 f5 }

  condition:
    any of them
}