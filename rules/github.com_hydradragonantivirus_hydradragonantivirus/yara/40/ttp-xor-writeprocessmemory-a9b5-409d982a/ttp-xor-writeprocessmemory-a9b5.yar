rule TTP_XOR_WriteProcessMemory_a9b5 {
  strings:
    $key_a9b5 = { fe c7 [2] cc e5 [2] ca d0 [2] e4 d0 [2] db cc }

  condition:
    any of them
}