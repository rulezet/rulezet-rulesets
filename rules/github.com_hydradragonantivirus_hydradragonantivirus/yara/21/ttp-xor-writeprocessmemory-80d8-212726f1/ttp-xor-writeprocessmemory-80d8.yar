rule TTP_XOR_WriteProcessMemory_80d8 {
  strings:
    $key_80d8 = { d7 aa [2] e5 88 [2] e3 bd [2] cd bd [2] f2 a1 }

  condition:
    any of them
}