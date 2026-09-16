rule TTP_XOR_WriteProcessMemory_bb47 {
  strings:
    $key_bb47 = { ec 35 [2] de 17 [2] d8 22 [2] f6 22 [2] c9 3e }

  condition:
    any of them
}