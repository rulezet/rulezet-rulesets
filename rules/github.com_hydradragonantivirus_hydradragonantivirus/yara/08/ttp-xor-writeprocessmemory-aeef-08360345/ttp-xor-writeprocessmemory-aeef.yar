rule TTP_XOR_WriteProcessMemory_aeef {
  strings:
    $key_aeef = { f9 9d [2] cb bf [2] cd 8a [2] e3 8a [2] dc 96 }

  condition:
    any of them
}