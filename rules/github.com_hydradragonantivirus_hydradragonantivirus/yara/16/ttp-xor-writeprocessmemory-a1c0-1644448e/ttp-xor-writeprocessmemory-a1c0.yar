rule TTP_XOR_WriteProcessMemory_a1c0 {
  strings:
    $key_a1c0 = { f6 b2 [2] c4 90 [2] c2 a5 [2] ec a5 [2] d3 b9 }

  condition:
    any of them
}