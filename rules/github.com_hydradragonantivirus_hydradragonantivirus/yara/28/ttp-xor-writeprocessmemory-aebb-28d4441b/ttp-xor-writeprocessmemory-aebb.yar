rule TTP_XOR_WriteProcessMemory_aebb {
  strings:
    $key_aebb = { f9 c9 [2] cb eb [2] cd de [2] e3 de [2] dc c2 }

  condition:
    any of them
}