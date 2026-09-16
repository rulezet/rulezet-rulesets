rule TTP_XOR_WriteProcessMemory_bbc7 {
  strings:
    $key_bbc7 = { ec b5 [2] de 97 [2] d8 a2 [2] f6 a2 [2] c9 be }

  condition:
    any of them
}