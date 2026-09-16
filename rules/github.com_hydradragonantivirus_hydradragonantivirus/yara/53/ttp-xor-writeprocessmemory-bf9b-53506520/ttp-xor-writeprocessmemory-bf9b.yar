rule TTP_XOR_WriteProcessMemory_bf9b {
  strings:
    $key_bf9b = { e8 e9 [2] da cb [2] dc fe [2] f2 fe [2] cd e2 }

  condition:
    any of them
}