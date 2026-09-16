rule TTP_XOR_WriteProcessMemory_a9a4 {
  strings:
    $key_a9a4 = { fe d6 [2] cc f4 [2] ca c1 [2] e4 c1 [2] db dd }

  condition:
    any of them
}