rule TTP_XOR_WriteProcessMemory_91d8 {
  strings:
    $key_91d8 = { c6 aa [2] f4 88 [2] f2 bd [2] dc bd [2] e3 a1 }

  condition:
    any of them
}