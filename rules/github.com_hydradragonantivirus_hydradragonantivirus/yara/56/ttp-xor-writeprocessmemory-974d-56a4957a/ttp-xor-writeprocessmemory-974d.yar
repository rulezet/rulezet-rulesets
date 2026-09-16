rule TTP_XOR_WriteProcessMemory_974d {
  strings:
    $key_974d = { c0 3f [2] f2 1d [2] f4 28 [2] da 28 [2] e5 34 }

  condition:
    any of them
}