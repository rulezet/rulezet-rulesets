rule TTP_XOR_WriteProcessMemory_a9c3 {
  strings:
    $key_a9c3 = { fe b1 [2] cc 93 [2] ca a6 [2] e4 a6 [2] db ba }

  condition:
    any of them
}