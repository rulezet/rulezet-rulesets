rule TTP_XOR_WriteProcessMemory_bf87 {
  strings:
    $key_bf87 = { e8 f5 [2] da d7 [2] dc e2 [2] f2 e2 [2] cd fe }

  condition:
    any of them
}