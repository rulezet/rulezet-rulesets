rule TTP_XOR_WriteProcessMemory_c8f0 {
  strings:
    $key_c8f0 = { 9f 82 [2] ad a0 [2] ab 95 [2] 85 95 [2] ba 89 }

  condition:
    any of them
}