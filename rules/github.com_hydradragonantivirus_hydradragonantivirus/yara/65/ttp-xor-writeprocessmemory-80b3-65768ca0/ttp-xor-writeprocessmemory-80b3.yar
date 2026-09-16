rule TTP_XOR_WriteProcessMemory_80b3 {
  strings:
    $key_80b3 = { d7 c1 [2] e5 e3 [2] e3 d6 [2] cd d6 [2] f2 ca }

  condition:
    any of them
}