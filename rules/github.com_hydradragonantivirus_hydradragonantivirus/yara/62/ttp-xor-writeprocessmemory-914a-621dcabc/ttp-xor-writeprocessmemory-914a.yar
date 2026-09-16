rule TTP_XOR_WriteProcessMemory_914a {
  strings:
    $key_914a = { c6 38 [2] f4 1a [2] f2 2f [2] dc 2f [2] e3 33 }

  condition:
    any of them
}