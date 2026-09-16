rule TTP_XOR_WriteProcessMemory_bb0f {
  strings:
    $key_bb0f = { ec 7d [2] de 5f [2] d8 6a [2] f6 6a [2] c9 76 }

  condition:
    any of them
}