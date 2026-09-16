rule TTP_XOR_WriteProcessMemory_a9c0 {
  strings:
    $key_a9c0 = { fe b2 [2] cc 90 [2] ca a5 [2] e4 a5 [2] db b9 }

  condition:
    any of them
}