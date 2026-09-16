rule TTP_XOR_WriteProcessMemory_935d {
  strings:
    $key_935d = { c4 2f [2] f6 0d [2] f0 38 [2] de 38 [2] e1 24 }

  condition:
    any of them
}