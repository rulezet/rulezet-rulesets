rule TTP_XOR_WriteProcessMemory_80fc {
  strings:
    $key_80fc = { d7 8e [2] e5 ac [2] e3 99 [2] cd 99 [2] f2 85 }

  condition:
    any of them
}