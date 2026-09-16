rule TTP_XOR_WriteProcessMemory_bb0d {
  strings:
    $key_bb0d = { ec 7f [2] de 5d [2] d8 68 [2] f6 68 [2] c9 74 }

  condition:
    any of them
}