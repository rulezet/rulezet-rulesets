rule TTP_XOR_WriteProcessMemory_afe7 {
  strings:
    $key_afe7 = { f8 95 [2] ca b7 [2] cc 82 [2] e2 82 [2] dd 9e }

  condition:
    any of them
}