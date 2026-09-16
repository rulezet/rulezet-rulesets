rule TTP_XOR_WriteProcessMemory_aecb {
  strings:
    $key_aecb = { f9 b9 [2] cb 9b [2] cd ae [2] e3 ae [2] dc b2 }

  condition:
    any of them
}