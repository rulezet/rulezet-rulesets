rule TTP_XOR_WriteProcessMemory_8045 {
  strings:
    $key_8045 = { d7 37 [2] e5 15 [2] e3 20 [2] cd 20 [2] f2 3c }

  condition:
    any of them
}