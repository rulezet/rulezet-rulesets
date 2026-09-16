rule TTP_XOR_WriteProcessMemory_afe6 {
  strings:
    $key_afe6 = { f8 94 [2] ca b6 [2] cc 83 [2] e2 83 [2] dd 9f }

  condition:
    any of them
}