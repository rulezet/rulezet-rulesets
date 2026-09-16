rule TTP_XOR_WriteProcessMemory_aedc {
  strings:
    $key_aedc = { f9 ae [2] cb 8c [2] cd b9 [2] e3 b9 [2] dc a5 }

  condition:
    any of them
}