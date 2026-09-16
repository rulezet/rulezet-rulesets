rule TTP_XOR_WriteProcessMemory_aeb6 {
  strings:
    $key_aeb6 = { f9 c4 [2] cb e6 [2] cd d3 [2] e3 d3 [2] dc cf }

  condition:
    any of them
}