rule TTP_XOR_WriteProcessMemory_bf88 {
  strings:
    $key_bf88 = { e8 fa [2] da d8 [2] dc ed [2] f2 ed [2] cd f1 }

  condition:
    any of them
}