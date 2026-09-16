rule TTP_XOR_WriteProcessMemory_8558 {
  strings:
    $key_8558 = { d2 2a [2] e0 08 [2] e6 3d [2] c8 3d [2] f7 21 }

  condition:
    any of them
}