rule TTP_XOR_WriteProcessMemory_a9d0 {
  strings:
    $key_a9d0 = { fe a2 [2] cc 80 [2] ca b5 [2] e4 b5 [2] db a9 }

  condition:
    any of them
}