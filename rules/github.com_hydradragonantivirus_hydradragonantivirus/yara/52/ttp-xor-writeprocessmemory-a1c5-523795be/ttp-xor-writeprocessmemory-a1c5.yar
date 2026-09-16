rule TTP_XOR_WriteProcessMemory_a1c5 {
  strings:
    $key_a1c5 = { f6 b7 [2] c4 95 [2] c2 a0 [2] ec a0 [2] d3 bc }

  condition:
    any of them
}