rule TTP_XOR_WriteProcessMemory_748a {
  strings:
    $key_748a = { 23 f8 [2] 11 da [2] 17 ef [2] 39 ef [2] 06 f3 }

  condition:
    any of them
}