rule TTP_XOR_WriteProcessMemory_aee8 {
  strings:
    $key_aee8 = { f9 9a [2] cb b8 [2] cd 8d [2] e3 8d [2] dc 91 }

  condition:
    any of them
}