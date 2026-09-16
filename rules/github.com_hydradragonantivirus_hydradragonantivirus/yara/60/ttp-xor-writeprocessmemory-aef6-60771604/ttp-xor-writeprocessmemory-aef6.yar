rule TTP_XOR_WriteProcessMemory_aef6 {
  strings:
    $key_aef6 = { f9 84 [2] cb a6 [2] cd 93 [2] e3 93 [2] dc 8f }

  condition:
    any of them
}