rule TTP_XOR_WriteProcessMemory_ae67 {
  strings:
    $key_ae67 = { f9 15 [2] cb 37 [2] cd 02 [2] e3 02 [2] dc 1e }

  condition:
    any of them
}