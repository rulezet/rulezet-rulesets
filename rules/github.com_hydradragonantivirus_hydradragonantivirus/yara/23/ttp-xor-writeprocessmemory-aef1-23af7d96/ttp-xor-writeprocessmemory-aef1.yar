rule TTP_XOR_WriteProcessMemory_aef1 {
  strings:
    $key_aef1 = { f9 83 [2] cb a1 [2] cd 94 [2] e3 94 [2] dc 88 }

  condition:
    any of them
}