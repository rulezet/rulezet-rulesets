rule TTP_XOR_WriteProcessMemory_a990 {
  strings:
    $key_a990 = { fe e2 [2] cc c0 [2] ca f5 [2] e4 f5 [2] db e9 }

  condition:
    any of them
}