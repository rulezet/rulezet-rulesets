rule TTP_XOR_WriteProcessMemory_a174 {
  strings:
    $key_a174 = { f6 06 [2] c4 24 [2] c2 11 [2] ec 11 [2] d3 0d }

  condition:
    any of them
}