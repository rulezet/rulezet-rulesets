rule TTP_XOR_WriteProcessMemory_aef3 {
  strings:
    $key_aef3 = { f9 81 [2] cb a3 [2] cd 96 [2] e3 96 [2] dc 8a }

  condition:
    any of them
}