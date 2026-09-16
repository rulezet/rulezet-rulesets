rule TTP_XOR_WriteProcessMemory_bf93 {
  strings:
    $key_bf93 = { e8 e1 [2] da c3 [2] dc f6 [2] f2 f6 [2] cd ea }

  condition:
    any of them
}