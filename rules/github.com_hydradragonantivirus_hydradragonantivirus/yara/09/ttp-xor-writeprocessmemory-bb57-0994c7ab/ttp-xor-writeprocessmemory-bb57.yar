rule TTP_XOR_WriteProcessMemory_bb57 {
  strings:
    $key_bb57 = { ec 25 [2] de 07 [2] d8 32 [2] f6 32 [2] c9 2e }

  condition:
    any of them
}