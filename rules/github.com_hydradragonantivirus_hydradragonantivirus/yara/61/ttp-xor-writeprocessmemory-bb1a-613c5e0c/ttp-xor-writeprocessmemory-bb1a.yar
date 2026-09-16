rule TTP_XOR_WriteProcessMemory_bb1a {
  strings:
    $key_bb1a = { ec 68 [2] de 4a [2] d8 7f [2] f6 7f [2] c9 63 }

  condition:
    any of them
}