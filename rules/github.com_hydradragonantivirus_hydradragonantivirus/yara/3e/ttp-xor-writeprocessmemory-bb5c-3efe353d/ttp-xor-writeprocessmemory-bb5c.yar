rule TTP_XOR_WriteProcessMemory_bb5c {
  strings:
    $key_bb5c = { ec 2e [2] de 0c [2] d8 39 [2] f6 39 [2] c9 25 }

  condition:
    any of them
}