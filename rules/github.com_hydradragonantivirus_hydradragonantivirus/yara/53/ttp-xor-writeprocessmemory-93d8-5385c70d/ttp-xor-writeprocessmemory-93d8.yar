rule TTP_XOR_WriteProcessMemory_93d8 {
  strings:
    $key_93d8 = { c4 aa [2] f6 88 [2] f0 bd [2] de bd [2] e1 a1 }

  condition:
    any of them
}