rule TTP_XOR_WriteProcessMemory_8776 {
  strings:
    $key_8776 = { d0 04 [2] e2 26 [2] e4 13 [2] ca 13 [2] f5 0f }

  condition:
    any of them
}