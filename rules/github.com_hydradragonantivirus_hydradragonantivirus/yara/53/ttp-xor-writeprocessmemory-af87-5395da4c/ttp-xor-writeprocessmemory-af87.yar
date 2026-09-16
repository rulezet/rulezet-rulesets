rule TTP_XOR_WriteProcessMemory_af87 {
  strings:
    $key_af87 = { f8 f5 [2] ca d7 [2] cc e2 [2] e2 e2 [2] dd fe }

  condition:
    any of them
}