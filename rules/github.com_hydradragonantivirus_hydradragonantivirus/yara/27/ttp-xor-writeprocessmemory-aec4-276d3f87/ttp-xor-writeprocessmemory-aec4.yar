rule TTP_XOR_WriteProcessMemory_aec4 {
  strings:
    $key_aec4 = { f9 b6 [2] cb 94 [2] cd a1 [2] e3 a1 [2] dc bd }

  condition:
    any of them
}