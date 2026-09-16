rule TTP_XOR_WriteProcessMemory_ae96 {
  strings:
    $key_ae96 = { f9 e4 [2] cb c6 [2] cd f3 [2] e3 f3 [2] dc ef }

  condition:
    any of them
}