rule TTP_XOR_WriteProcessMemory_bbc4 {
  strings:
    $key_bbc4 = { ec b6 [2] de 94 [2] d8 a1 [2] f6 a1 [2] c9 bd }

  condition:
    any of them
}