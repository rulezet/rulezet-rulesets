rule TTP_XOR_WriteProcessMemory_bbc6 {
  strings:
    $key_bbc6 = { ec b4 [2] de 96 [2] d8 a3 [2] f6 a3 [2] c9 bf }

  condition:
    any of them
}