rule TTP_XOR_WriteProcessMemory_804d {
  strings:
    $key_804d = { d7 3f [2] e5 1d [2] e3 28 [2] cd 28 [2] f2 34 }

  condition:
    any of them
}