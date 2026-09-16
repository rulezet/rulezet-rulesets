rule TTP_XOR_WriteProcessMemory_bf8c {
  strings:
    $key_bf8c = { e8 fe [2] da dc [2] dc e9 [2] f2 e9 [2] cd f5 }

  condition:
    any of them
}