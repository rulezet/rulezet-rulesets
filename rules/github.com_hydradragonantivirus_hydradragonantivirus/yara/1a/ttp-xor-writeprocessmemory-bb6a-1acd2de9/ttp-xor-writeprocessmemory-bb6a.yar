rule TTP_XOR_WriteProcessMemory_bb6a {
  strings:
    $key_bb6a = { ec 18 [2] de 3a [2] d8 0f [2] f6 0f [2] c9 13 }

  condition:
    any of them
}