rule TTP_XOR_WriteProcessMemory_bbca {
  strings:
    $key_bbca = { ec b8 [2] de 9a [2] d8 af [2] f6 af [2] c9 b3 }

  condition:
    any of them
}