rule TTP_XOR_WriteProcessMemory_950d {
  strings:
    $key_950d = { c2 7f [2] f0 5d [2] f6 68 [2] d8 68 [2] e7 74 }

  condition:
    any of them
}