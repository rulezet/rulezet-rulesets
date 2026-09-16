rule TTP_XOR_WriteProcessMemory_850d {
  strings:
    $key_850d = { d2 7f [2] e0 5d [2] e6 68 [2] c8 68 [2] f7 74 }

  condition:
    any of them
}