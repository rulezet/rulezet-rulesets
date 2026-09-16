rule TTP_XOR_WriteProcessMemory_bf21 {
  strings:
    $key_bf21 = { e8 53 [2] da 71 [2] dc 44 [2] f2 44 [2] cd 58 }

  condition:
    any of them
}