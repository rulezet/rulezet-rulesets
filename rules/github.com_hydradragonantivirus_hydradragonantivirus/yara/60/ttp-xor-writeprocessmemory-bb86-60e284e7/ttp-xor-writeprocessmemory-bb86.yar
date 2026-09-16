rule TTP_XOR_WriteProcessMemory_bb86 {
  strings:
    $key_bb86 = { ec f4 [2] de d6 [2] d8 e3 [2] f6 e3 [2] c9 ff }

  condition:
    any of them
}