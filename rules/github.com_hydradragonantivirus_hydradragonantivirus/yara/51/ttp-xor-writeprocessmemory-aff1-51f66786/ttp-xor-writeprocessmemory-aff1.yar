rule TTP_XOR_WriteProcessMemory_aff1 {
  strings:
    $key_aff1 = { f8 83 [2] ca a1 [2] cc 94 [2] e2 94 [2] dd 88 }

  condition:
    any of them
}