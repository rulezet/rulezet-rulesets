rule TTP_XOR_WriteProcessMemory_aff5 {
  strings:
    $key_aff5 = { f8 87 [2] ca a5 [2] cc 90 [2] e2 90 [2] dd 8c }

  condition:
    any of them
}