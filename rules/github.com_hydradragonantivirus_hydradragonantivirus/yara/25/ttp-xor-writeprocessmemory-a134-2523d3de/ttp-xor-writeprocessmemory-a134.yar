rule TTP_XOR_WriteProcessMemory_a134 {
  strings:
    $key_a134 = { f6 46 [2] c4 64 [2] c2 51 [2] ec 51 [2] d3 4d }

  condition:
    any of them
}