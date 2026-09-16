rule TTP_XOR_WriteProcessMemory_971a {
  strings:
    $key_971a = { c0 68 [2] f2 4a [2] f4 7f [2] da 7f [2] e5 63 }

  condition:
    any of them
}