rule TTP_XOR_WriteProcessMemory_a182 {
  strings:
    $key_a182 = { f6 f0 [2] c4 d2 [2] c2 e7 [2] ec e7 [2] d3 fb }

  condition:
    any of them
}