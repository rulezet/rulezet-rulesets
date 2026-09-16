rule TTP_XOR_WriteProcessMemory_a170 {
  strings:
    $key_a170 = { f6 02 [2] c4 20 [2] c2 15 [2] ec 15 [2] d3 09 }

  condition:
    any of them
}