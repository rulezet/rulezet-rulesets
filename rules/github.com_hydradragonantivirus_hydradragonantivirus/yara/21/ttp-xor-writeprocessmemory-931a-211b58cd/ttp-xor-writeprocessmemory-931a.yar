rule TTP_XOR_WriteProcessMemory_931a {
  strings:
    $key_931a = { c4 68 [2] f6 4a [2] f0 7f [2] de 7f [2] e1 63 }

  condition:
    any of them
}