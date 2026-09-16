rule TTP_XOR_WriteProcessMemory_aba1 {
  strings:
    $key_aba1 = { fc d3 [2] ce f1 [2] c8 c4 [2] e6 c4 [2] d9 d8 }

  condition:
    any of them
}