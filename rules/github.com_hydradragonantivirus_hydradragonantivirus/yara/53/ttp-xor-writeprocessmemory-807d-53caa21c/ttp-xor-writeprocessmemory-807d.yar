rule TTP_XOR_WriteProcessMemory_807d {
  strings:
    $key_807d = { d7 0f [2] e5 2d [2] e3 18 [2] cd 18 [2] f2 04 }

  condition:
    any of them
}