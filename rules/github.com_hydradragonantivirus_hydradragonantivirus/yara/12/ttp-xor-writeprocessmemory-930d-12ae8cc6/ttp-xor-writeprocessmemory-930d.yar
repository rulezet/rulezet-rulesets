rule TTP_XOR_WriteProcessMemory_930d {
  strings:
    $key_930d = { c4 7f [2] f6 5d [2] f0 68 [2] de 68 [2] e1 74 }

  condition:
    any of them
}