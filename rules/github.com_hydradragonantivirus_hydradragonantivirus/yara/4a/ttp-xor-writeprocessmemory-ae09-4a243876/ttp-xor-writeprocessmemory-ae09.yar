rule TTP_XOR_WriteProcessMemory_ae09 {
  strings:
    $key_ae09 = { f9 7b [2] cb 59 [2] cd 6c [2] e3 6c [2] dc 70 }

  condition:
    any of them
}