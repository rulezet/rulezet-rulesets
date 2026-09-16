rule TTP_XOR_WriteProcessMemory_bb2a {
  strings:
    $key_bb2a = { ec 58 [2] de 7a [2] d8 4f [2] f6 4f [2] c9 53 }

  condition:
    any of them
}