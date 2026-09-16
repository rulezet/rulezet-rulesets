rule TTP_XOR_WriteProcessMemory_80c7 {
  strings:
    $key_80c7 = { d7 b5 [2] e5 97 [2] e3 a2 [2] cd a2 [2] f2 be }

  condition:
    any of them
}