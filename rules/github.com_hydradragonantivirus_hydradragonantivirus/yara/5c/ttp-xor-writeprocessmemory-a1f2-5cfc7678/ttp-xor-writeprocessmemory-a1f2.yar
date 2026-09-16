rule TTP_XOR_WriteProcessMemory_a1f2 {
  strings:
    $key_a1f2 = { f6 80 [2] c4 a2 [2] c2 97 [2] ec 97 [2] d3 8b }

  condition:
    any of them
}