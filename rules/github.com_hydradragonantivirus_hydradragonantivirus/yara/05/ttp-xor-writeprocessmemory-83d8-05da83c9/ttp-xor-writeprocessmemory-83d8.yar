rule TTP_XOR_WriteProcessMemory_83d8 {
  strings:
    $key_83d8 = { d4 aa [2] e6 88 [2] e0 bd [2] ce bd [2] f1 a1 }

  condition:
    any of them
}