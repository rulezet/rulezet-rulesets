rule TTP_XOR_WriteProcessMemory_80d7 {
  strings:
    $key_80d7 = { d7 a5 [2] e5 87 [2] e3 b2 [2] cd b2 [2] f2 ae }

  condition:
    any of them
}