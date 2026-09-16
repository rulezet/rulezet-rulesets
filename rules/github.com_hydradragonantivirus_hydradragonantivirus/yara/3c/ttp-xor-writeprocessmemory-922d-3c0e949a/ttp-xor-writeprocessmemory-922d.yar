rule TTP_XOR_WriteProcessMemory_922d {
  strings:
    $key_922d = { c5 5f [2] f7 7d [2] f1 48 [2] df 48 [2] e0 54 }

  condition:
    any of them
}