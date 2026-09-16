rule TTP_XOR_WriteProcessMemory_bccd {
  strings:
    $key_bccd = { eb bf [2] d9 9d [2] df a8 [2] f1 a8 [2] ce b4 }

  condition:
    any of them
}