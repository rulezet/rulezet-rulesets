rule TTP_XOR_WriteProcessMemory_a1e6 {
  strings:
    $key_a1e6 = { f6 94 [2] c4 b6 [2] c2 83 [2] ec 83 [2] d3 9f }

  condition:
    any of them
}