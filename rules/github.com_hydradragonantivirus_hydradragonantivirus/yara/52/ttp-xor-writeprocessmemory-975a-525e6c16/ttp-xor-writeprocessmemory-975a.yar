rule TTP_XOR_WriteProcessMemory_975a {
  strings:
    $key_975a = { c0 28 [2] f2 0a [2] f4 3f [2] da 3f [2] e5 23 }

  condition:
    any of them
}