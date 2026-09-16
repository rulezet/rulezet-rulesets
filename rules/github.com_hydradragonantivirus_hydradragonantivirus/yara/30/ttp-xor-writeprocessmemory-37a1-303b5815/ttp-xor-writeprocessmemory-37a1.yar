rule TTP_XOR_WriteProcessMemory_37a1 {
  strings:
    $key_37a1 = { 60 d3 [2] 52 f1 [2] 54 c4 [2] 7a c4 [2] 45 d8 }

  condition:
    any of them
}