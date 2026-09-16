rule TTP_XOR_WriteProcessMemory_80c5 {
  strings:
    $key_80c5 = { d7 b7 [2] e5 95 [2] e3 a0 [2] cd a0 [2] f2 bc }

  condition:
    any of them
}