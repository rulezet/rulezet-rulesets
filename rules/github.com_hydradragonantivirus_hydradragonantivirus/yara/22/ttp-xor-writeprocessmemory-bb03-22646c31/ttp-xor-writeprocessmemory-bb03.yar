rule TTP_XOR_WriteProcessMemory_bb03 {
  strings:
    $key_bb03 = { ec 71 [2] de 53 [2] d8 66 [2] f6 66 [2] c9 7a }

  condition:
    any of them
}