rule TTP_XOR_WriteProcessMemory_a1c3 {
  strings:
    $key_a1c3 = { f6 b1 [2] c4 93 [2] c2 a6 [2] ec a6 [2] d3 ba }

  condition:
    any of them
}