rule TTP_XOR_WriteProcessMemory_bbc5 {
  strings:
    $key_bbc5 = { ec b7 [2] de 95 [2] d8 a0 [2] f6 a0 [2] c9 bc }

  condition:
    any of them
}