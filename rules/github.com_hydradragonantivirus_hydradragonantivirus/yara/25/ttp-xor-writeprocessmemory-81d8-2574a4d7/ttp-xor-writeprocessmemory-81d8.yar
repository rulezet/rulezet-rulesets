rule TTP_XOR_WriteProcessMemory_81d8 {
  strings:
    $key_81d8 = { d6 aa [2] e4 88 [2] e2 bd [2] cc bd [2] f3 a1 }

  condition:
    any of them
}