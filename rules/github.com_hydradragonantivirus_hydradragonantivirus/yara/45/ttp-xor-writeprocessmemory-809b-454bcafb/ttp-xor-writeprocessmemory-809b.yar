rule TTP_XOR_WriteProcessMemory_809b {
  strings:
    $key_809b = { d7 e9 [2] e5 cb [2] e3 fe [2] cd fe [2] f2 e2 }

  condition:
    any of them
}