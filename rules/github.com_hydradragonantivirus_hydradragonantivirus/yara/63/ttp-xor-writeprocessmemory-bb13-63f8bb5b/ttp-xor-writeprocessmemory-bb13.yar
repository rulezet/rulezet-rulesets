rule TTP_XOR_WriteProcessMemory_bb13 {
  strings:
    $key_bb13 = { ec 61 [2] de 43 [2] d8 76 [2] f6 76 [2] c9 6a }

  condition:
    any of them
}