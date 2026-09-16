rule TTP_XOR_WriteProcessMemory_bb5f {
  strings:
    $key_bb5f = { ec 2d [2] de 0f [2] d8 3a [2] f6 3a [2] c9 26 }

  condition:
    any of them
}