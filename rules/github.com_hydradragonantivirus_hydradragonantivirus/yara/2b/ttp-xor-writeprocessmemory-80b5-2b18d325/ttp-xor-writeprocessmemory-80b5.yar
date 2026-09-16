rule TTP_XOR_WriteProcessMemory_80b5 {
  strings:
    $key_80b5 = { d7 c7 [2] e5 e5 [2] e3 d0 [2] cd d0 [2] f2 cc }

  condition:
    any of them
}