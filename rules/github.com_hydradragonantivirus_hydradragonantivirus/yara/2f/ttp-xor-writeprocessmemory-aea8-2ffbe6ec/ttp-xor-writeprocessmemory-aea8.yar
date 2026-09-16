rule TTP_XOR_WriteProcessMemory_aea8 {
  strings:
    $key_aea8 = { f9 da [2] cb f8 [2] cd cd [2] e3 cd [2] dc d1 }

  condition:
    any of them
}