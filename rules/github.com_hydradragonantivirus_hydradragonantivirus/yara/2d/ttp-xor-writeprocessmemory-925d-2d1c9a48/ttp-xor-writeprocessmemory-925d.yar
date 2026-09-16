rule TTP_XOR_WriteProcessMemory_925d {
  strings:
    $key_925d = { c5 2f [2] f7 0d [2] f1 38 [2] df 38 [2] e0 24 }

  condition:
    any of them
}