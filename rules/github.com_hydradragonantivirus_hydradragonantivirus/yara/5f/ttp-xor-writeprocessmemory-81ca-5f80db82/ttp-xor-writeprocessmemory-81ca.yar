rule TTP_XOR_WriteProcessMemory_81ca {
  strings:
    $key_81ca = { d6 b8 [2] e4 9a [2] e2 af [2] cc af [2] f3 b3 }

  condition:
    any of them
}