rule TTP_XOR_WriteProcessMemory_85ca {
  strings:
    $key_85ca = { d2 b8 [2] e0 9a [2] e6 af [2] c8 af [2] f7 b3 }

  condition:
    any of them
}