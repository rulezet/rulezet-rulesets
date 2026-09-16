rule TTP_XOR_WriteProcessMemory_bb2e {
  strings:
    $key_bb2e = { ec 5c [2] de 7e [2] d8 4b [2] f6 4b [2] c9 57 }

  condition:
    any of them
}