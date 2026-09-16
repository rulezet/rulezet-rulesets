rule TTP_XOR_WriteProcessMemory_a1b3 {
  strings:
    $key_a1b3 = { f6 c1 [2] c4 e3 [2] c2 d6 [2] ec d6 [2] d3 ca }

  condition:
    any of them
}