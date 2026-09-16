rule TTP_XOR_WriteProcessMemory_8518 {
  strings:
    $key_8518 = { d2 6a [2] e0 48 [2] e6 7d [2] c8 7d [2] f7 61 }

  condition:
    any of them
}