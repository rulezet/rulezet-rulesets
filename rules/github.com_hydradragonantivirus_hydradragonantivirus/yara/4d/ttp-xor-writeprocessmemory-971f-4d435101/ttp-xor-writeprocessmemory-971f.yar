rule TTP_XOR_WriteProcessMemory_971f {
  strings:
    $key_971f = { c0 6d [2] f2 4f [2] f4 7a [2] da 7a [2] e5 66 }

  condition:
    any of them
}