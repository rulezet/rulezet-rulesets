rule TTP_XOR_WriteProcessMemory_bf86 {
  strings:
    $key_bf86 = { e8 f4 [2] da d6 [2] dc e3 [2] f2 e3 [2] cd ff }

  condition:
    any of them
}