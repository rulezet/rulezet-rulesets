rule TTP_XOR_WriteProcessMemory_a9c2 {
  strings:
    $key_a9c2 = { fe b0 [2] cc 92 [2] ca a7 [2] e4 a7 [2] db bb }

  condition:
    any of them
}