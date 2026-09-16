rule TTP_XOR_WriteProcessMemory_97d8 {
  strings:
    $key_97d8 = { c0 aa [2] f2 88 [2] f4 bd [2] da bd [2] e5 a1 }

  condition:
    any of them
}