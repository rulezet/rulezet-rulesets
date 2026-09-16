rule TTP_XOR_WriteProcessMemory_aeda {
  strings:
    $key_aeda = { f9 a8 [2] cb 8a [2] cd bf [2] e3 bf [2] dc a3 }

  condition:
    any of them
}