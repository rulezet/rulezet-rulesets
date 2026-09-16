rule TTP_XOR_WriteProcessMemory_bb15 {
  strings:
    $key_bb15 = { ec 67 [2] de 45 [2] d8 70 [2] f6 70 [2] c9 6c }

  condition:
    any of them
}