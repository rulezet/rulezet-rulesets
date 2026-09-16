rule TTP_XOR_WriteProcessMemory_a123 {
  strings:
    $key_a123 = { f6 51 [2] c4 73 [2] c2 46 [2] ec 46 [2] d3 5a }

  condition:
    any of them
}