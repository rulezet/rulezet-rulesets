rule TTP_XOR_WriteProcessMemory_bb7e {
  strings:
    $key_bb7e = { ec 0c [2] de 2e [2] d8 1b [2] f6 1b [2] c9 07 }

  condition:
    any of them
}