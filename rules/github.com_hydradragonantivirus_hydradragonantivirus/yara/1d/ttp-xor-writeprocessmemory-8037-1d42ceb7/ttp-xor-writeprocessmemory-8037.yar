rule TTP_XOR_WriteProcessMemory_8037 {
  strings:
    $key_8037 = { d7 45 [2] e5 67 [2] e3 52 [2] cd 52 [2] f2 4e }

  condition:
    any of them
}