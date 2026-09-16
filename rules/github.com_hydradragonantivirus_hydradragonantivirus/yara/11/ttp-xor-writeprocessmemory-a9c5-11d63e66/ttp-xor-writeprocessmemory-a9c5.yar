rule TTP_XOR_WriteProcessMemory_a9c5 {
  strings:
    $key_a9c5 = { fe b7 [2] cc 95 [2] ca a0 [2] e4 a0 [2] db bc }

  condition:
    any of them
}