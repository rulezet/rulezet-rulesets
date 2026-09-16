rule TTP_XOR_WriteProcessMemory_97fa {
  strings:
    $key_97fa = { c0 88 [2] f2 aa [2] f4 9f [2] da 9f [2] e5 83 }

  condition:
    any of them
}