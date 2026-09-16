rule TTP_XOR_WriteProcessMemory_bb37 {
  strings:
    $key_bb37 = { ec 45 [2] de 67 [2] d8 52 [2] f6 52 [2] c9 4e }

  condition:
    any of them
}