rule TTP_XOR_WriteProcessMemory_95cf {
  strings:
    $key_95cf = { c2 bd [2] f0 9f [2] f6 aa [2] d8 aa [2] e7 b6 }

  condition:
    any of them
}