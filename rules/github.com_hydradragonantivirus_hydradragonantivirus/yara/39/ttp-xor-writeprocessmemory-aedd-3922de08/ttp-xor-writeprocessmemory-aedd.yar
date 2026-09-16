rule TTP_XOR_WriteProcessMemory_aedd {
  strings:
    $key_aedd = { f9 af [2] cb 8d [2] cd b8 [2] e3 b8 [2] dc a4 }

  condition:
    any of them
}