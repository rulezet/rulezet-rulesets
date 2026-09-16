rule TTP_XOR_WriteProcessMemory_a1d5 {
  strings:
    $key_a1d5 = { f6 a7 [2] c4 85 [2] c2 b0 [2] ec b0 [2] d3 ac }

  condition:
    any of them
}