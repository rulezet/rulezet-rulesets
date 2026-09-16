rule TTP_XOR_WriteProcessMemory_82d8 {
  strings:
    $key_82d8 = { d5 aa [2] e7 88 [2] e1 bd [2] cf bd [2] f0 a1 }

  condition:
    any of them
}