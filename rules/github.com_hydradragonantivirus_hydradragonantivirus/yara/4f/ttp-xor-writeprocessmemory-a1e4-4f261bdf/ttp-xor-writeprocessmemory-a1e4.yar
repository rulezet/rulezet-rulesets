rule TTP_XOR_WriteProcessMemory_a1e4 {
  strings:
    $key_a1e4 = { f6 96 [2] c4 b4 [2] c2 81 [2] ec 81 [2] d3 9d }

  condition:
    any of them
}