rule TTP_XOR_WriteProcessMemory_badd {
  strings:
    $key_badd = { ed af [2] df 8d [2] d9 b8 [2] f7 b8 [2] c8 a4 }

  condition:
    any of them
}