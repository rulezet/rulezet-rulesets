rule TTP_XOR_WriteProcessMemory_a9c6 {
  strings:
    $key_a9c6 = { fe b4 [2] cc 96 [2] ca a3 [2] e4 a3 [2] db bf }

  condition:
    any of them
}