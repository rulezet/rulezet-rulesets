rule TTP_XOR_WriteProcessMemory_a143 {
  strings:
    $key_a143 = { f6 31 [2] c4 13 [2] c2 26 [2] ec 26 [2] d3 3a }

  condition:
    any of them
}