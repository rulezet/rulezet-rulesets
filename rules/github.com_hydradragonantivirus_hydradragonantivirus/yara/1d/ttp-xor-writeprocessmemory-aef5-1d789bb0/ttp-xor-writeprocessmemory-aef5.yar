rule TTP_XOR_WriteProcessMemory_aef5 {
  strings:
    $key_aef5 = { f9 87 [2] cb a5 [2] cd 90 [2] e3 90 [2] dc 8c }

  condition:
    any of them
}