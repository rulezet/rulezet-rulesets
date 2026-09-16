rule TTP_XOR_WriteProcessMemory_bb4a {
  strings:
    $key_bb4a = { ec 38 [2] de 1a [2] d8 2f [2] f6 2f [2] c9 33 }

  condition:
    any of them
}