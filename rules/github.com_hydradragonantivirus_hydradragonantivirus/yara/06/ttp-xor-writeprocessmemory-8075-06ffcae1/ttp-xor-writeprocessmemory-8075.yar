rule TTP_XOR_WriteProcessMemory_8075 {
  strings:
    $key_8075 = { d7 07 [2] e5 25 [2] e3 10 [2] cd 10 [2] f2 0c }

  condition:
    any of them
}