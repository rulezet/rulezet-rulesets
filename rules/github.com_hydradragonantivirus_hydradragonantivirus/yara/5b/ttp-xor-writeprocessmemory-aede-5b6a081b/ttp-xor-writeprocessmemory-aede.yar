rule TTP_XOR_WriteProcessMemory_aede {
  strings:
    $key_aede = { f9 ac [2] cb 8e [2] cd bb [2] e3 bb [2] dc a7 }

  condition:
    any of them
}