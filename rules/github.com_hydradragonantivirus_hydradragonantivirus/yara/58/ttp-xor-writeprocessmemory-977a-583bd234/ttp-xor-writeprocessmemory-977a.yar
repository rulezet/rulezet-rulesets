rule TTP_XOR_WriteProcessMemory_977a {
  strings:
    $key_977a = { c0 08 [2] f2 2a [2] f4 1f [2] da 1f [2] e5 03 }

  condition:
    any of them
}