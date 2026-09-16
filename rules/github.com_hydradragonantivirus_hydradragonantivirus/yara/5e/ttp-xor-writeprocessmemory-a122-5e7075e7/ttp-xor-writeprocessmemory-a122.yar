rule TTP_XOR_WriteProcessMemory_a122 {
  strings:
    $key_a122 = { f6 50 [2] c4 72 [2] c2 47 [2] ec 47 [2] d3 5b }

  condition:
    any of them
}