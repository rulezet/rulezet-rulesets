rule TTP_XOR_WriteProcessMemory_a8ad {
  strings:
    $key_a8ad = { ff df [2] cd fd [2] cb c8 [2] e5 c8 [2] da d4 }

  condition:
    any of them
}