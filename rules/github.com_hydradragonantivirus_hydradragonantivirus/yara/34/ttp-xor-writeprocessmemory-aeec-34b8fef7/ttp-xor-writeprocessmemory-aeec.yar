rule TTP_XOR_WriteProcessMemory_aeec {
  strings:
    $key_aeec = { f9 9e [2] cb bc [2] cd 89 [2] e3 89 [2] dc 95 }

  condition:
    any of them
}