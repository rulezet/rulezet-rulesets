rule TTP_XOR_WriteProcessMemory_bf71 {
  strings:
    $key_bf71 = { e8 03 [2] da 21 [2] dc 14 [2] f2 14 [2] cd 08 }

  condition:
    any of them
}