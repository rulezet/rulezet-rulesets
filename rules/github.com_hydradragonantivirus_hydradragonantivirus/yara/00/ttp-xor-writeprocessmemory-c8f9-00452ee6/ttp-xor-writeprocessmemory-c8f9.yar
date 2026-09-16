rule TTP_XOR_WriteProcessMemory_c8f9 {
  strings:
    $key_c8f9 = { 9f 8b [2] ad a9 [2] ab 9c [2] 85 9c [2] ba 80 }

  condition:
    any of them
}