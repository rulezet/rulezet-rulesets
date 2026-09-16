rule TTP_XOR_WriteProcessMemory_a1f3 {
  strings:
    $key_a1f3 = { f6 81 [2] c4 a3 [2] c2 96 [2] ec 96 [2] d3 8a }

  condition:
    any of them
}