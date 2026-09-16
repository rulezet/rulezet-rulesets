rule TTP_XOR_WriteProcessMemory_8094 {
  strings:
    $key_8094 = { d7 e6 [2] e5 c4 [2] e3 f1 [2] cd f1 [2] f2 ed }

  condition:
    any of them
}