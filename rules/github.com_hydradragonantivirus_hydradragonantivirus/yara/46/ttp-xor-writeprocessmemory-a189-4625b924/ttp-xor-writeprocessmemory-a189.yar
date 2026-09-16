rule TTP_XOR_WriteProcessMemory_a189 {
  strings:
    $key_a189 = { f6 fb [2] c4 d9 [2] c2 ec [2] ec ec [2] d3 f0 }

  condition:
    any of them
}