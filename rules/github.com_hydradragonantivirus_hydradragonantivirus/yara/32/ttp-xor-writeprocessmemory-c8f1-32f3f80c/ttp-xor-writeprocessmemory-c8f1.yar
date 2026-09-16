rule TTP_XOR_WriteProcessMemory_c8f1 {
  strings:
    $key_c8f1 = { 9f 83 [2] ad a1 [2] ab 94 [2] 85 94 [2] ba 88 }

  condition:
    any of them
}