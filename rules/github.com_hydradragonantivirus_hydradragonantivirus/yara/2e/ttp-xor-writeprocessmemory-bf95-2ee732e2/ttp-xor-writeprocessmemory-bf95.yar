rule TTP_XOR_WriteProcessMemory_bf95 {
  strings:
    $key_bf95 = { e8 e7 [2] da c5 [2] dc f0 [2] f2 f0 [2] cd ec }

  condition:
    any of them
}