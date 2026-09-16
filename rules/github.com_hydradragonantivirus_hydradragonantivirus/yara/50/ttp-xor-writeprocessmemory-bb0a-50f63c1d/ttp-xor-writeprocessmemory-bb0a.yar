rule TTP_XOR_WriteProcessMemory_bb0a {
  strings:
    $key_bb0a = { ec 78 [2] de 5a [2] d8 6f [2] f6 6f [2] c9 73 }

  condition:
    any of them
}