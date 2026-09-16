rule TTP_XOR_WriteProcessMemory_af83 {
  strings:
    $key_af83 = { f8 f1 [2] ca d3 [2] cc e6 [2] e2 e6 [2] dd fa }

  condition:
    any of them
}