rule TTP_XOR_WriteProcessMemory_bf85 {
  strings:
    $key_bf85 = { e8 f7 [2] da d5 [2] dc e0 [2] f2 e0 [2] cd fc }

  condition:
    any of them
}