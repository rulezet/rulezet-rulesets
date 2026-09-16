rule TTP_XOR_WriteProcessMemory_aef4 {
  strings:
    $key_aef4 = { f9 86 [2] cb a4 [2] cd 91 [2] e3 91 [2] dc 8d }

  condition:
    any of them
}