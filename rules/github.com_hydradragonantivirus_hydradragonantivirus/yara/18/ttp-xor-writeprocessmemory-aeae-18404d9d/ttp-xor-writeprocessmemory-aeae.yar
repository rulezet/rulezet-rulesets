rule TTP_XOR_WriteProcessMemory_aeae {
  strings:
    $key_aeae = { f9 dc [2] cb fe [2] cd cb [2] e3 cb [2] dc d7 }

  condition:
    any of them
}