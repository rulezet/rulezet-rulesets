rule TTP_XOR_WriteProcessMemory_a1e3 {
  strings:
    $key_a1e3 = { f6 91 [2] c4 b3 [2] c2 86 [2] ec 86 [2] d3 9a }

  condition:
    any of them
}