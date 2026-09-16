rule TTP_XOR_WriteProcessMemory_852d {
  strings:
    $key_852d = { d2 5f [2] e0 7d [2] e6 48 [2] c8 48 [2] f7 54 }

  condition:
    any of them
}