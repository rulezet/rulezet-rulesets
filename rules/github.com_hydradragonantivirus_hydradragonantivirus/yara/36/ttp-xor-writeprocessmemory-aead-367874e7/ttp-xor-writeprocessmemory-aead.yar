rule TTP_XOR_WriteProcessMemory_aead {
  strings:
    $key_aead = { f9 df [2] cb fd [2] cd c8 [2] e3 c8 [2] dc d4 }

  condition:
    any of them
}