rule TTP_XOR_WriteProcessMemory_80bf {
  strings:
    $key_80bf = { d7 cd [2] e5 ef [2] e3 da [2] cd da [2] f2 c6 }

  condition:
    any of them
}