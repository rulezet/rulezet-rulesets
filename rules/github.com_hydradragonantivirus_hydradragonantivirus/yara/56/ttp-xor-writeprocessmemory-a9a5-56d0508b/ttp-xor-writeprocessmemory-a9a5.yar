rule TTP_XOR_WriteProcessMemory_a9a5 {
  strings:
    $key_a9a5 = { fe d7 [2] cc f5 [2] ca c0 [2] e4 c0 [2] db dc }

  condition:
    any of them
}