rule TTP_XOR_WriteProcessMemory_8348 {
  strings:
    $key_8348 = { d4 3a [2] e6 18 [2] e0 2d [2] ce 2d [2] f1 31 }

  condition:
    any of them
}