rule TTP_XOR_WriteProcessMemory_bbcb {
  strings:
    $key_bbcb = { ec b9 [2] de 9b [2] d8 ae [2] f6 ae [2] c9 b2 }

  condition:
    any of them
}