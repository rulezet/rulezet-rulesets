rule TTP_XOR_WriteProcessMemory_a9b3 {
  strings:
    $key_a9b3 = { fe c1 [2] cc e3 [2] ca d6 [2] e4 d6 [2] db ca }

  condition:
    any of them
}