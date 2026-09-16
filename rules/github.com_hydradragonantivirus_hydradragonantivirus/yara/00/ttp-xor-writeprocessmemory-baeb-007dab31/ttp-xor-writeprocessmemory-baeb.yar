rule TTP_XOR_WriteProcessMemory_baeb {
  strings:
    $key_baeb = { ed 99 [2] df bb [2] d9 8e [2] f7 8e [2] c8 92 }

  condition:
    any of them
}