rule TTP_XOR_WriteProcessMemory_aef9 {
  strings:
    $key_aef9 = { f9 8b [2] cb a9 [2] cd 9c [2] e3 9c [2] dc 80 }

  condition:
    any of them
}