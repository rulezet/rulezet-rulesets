rule TTP_XOR_WriteProcessMemory_aee7 {
  strings:
    $key_aee7 = { f9 95 [2] cb b7 [2] cd 82 [2] e3 82 [2] dc 9e }

  condition:
    any of them
}