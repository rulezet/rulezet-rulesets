rule TTP_XOR_WriteProcessMemory_92ca {
  strings:
    $key_92ca = { c5 b8 [2] f7 9a [2] f1 af [2] df af [2] e0 b3 }

  condition:
    any of them
}