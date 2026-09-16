rule TTP_XOR_WriteProcessMemory_90db {
  strings:
    $key_90db = { c7 a9 [2] f5 8b [2] f3 be [2] dd be [2] e2 a2 }

  condition:
    any of them
}