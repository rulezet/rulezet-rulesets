rule TTP_XOR_WriteProcessMemory_bb5b {
  strings:
    $key_bb5b = { ec 29 [2] de 0b [2] d8 3e [2] f6 3e [2] c9 22 }

  condition:
    any of them
}