rule TTP_XOR_WriteProcessMemory_851d {
  strings:
    $key_851d = { d2 6f [2] e0 4d [2] e6 78 [2] c8 78 [2] f7 64 }

  condition:
    any of them
}