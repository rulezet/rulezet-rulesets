rule TTP_XOR_WriteProcessMemory_a1d6 {
  strings:
    $key_a1d6 = { f6 a4 [2] c4 86 [2] c2 b3 [2] ec b3 [2] d3 af }

  condition:
    any of them
}