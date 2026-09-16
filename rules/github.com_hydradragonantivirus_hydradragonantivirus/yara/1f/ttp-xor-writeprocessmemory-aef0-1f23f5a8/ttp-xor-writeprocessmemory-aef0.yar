rule TTP_XOR_WriteProcessMemory_aef0 {
  strings:
    $key_aef0 = { f9 82 [2] cb a0 [2] cd 95 [2] e3 95 [2] dc 89 }

  condition:
    any of them
}