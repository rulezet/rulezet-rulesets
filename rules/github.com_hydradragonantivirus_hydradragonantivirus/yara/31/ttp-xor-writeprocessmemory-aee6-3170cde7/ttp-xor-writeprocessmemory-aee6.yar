rule TTP_XOR_WriteProcessMemory_aee6 {
  strings:
    $key_aee6 = { f9 94 [2] cb b6 [2] cd 83 [2] e3 83 [2] dc 9f }

  condition:
    any of them
}