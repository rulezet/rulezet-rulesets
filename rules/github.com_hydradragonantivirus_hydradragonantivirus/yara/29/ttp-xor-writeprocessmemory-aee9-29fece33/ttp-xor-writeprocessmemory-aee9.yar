rule TTP_XOR_WriteProcessMemory_aee9 {
  strings:
    $key_aee9 = { f9 9b [2] cb b9 [2] cd 8c [2] e3 8c [2] dc 90 }

  condition:
    any of them
}