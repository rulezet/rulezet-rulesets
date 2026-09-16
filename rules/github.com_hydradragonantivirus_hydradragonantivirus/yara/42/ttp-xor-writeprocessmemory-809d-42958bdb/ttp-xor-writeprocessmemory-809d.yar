rule TTP_XOR_WriteProcessMemory_809d {
  strings:
    $key_809d = { d7 ef [2] e5 cd [2] e3 f8 [2] cd f8 [2] f2 e4 }

  condition:
    any of them
}