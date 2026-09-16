rule TTP_XOR_WriteProcessMemory_aeb2 {
  strings:
    $key_aeb2 = { f9 c0 [2] cb e2 [2] cd d7 [2] e3 d7 [2] dc cb }

  condition:
    any of them
}