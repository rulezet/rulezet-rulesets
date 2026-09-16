rule TTP_XOR_WriteProcessMemory_972a {
  strings:
    $key_972a = { c0 58 [2] f2 7a [2] f4 4f [2] da 4f [2] e5 53 }

  condition:
    any of them
}