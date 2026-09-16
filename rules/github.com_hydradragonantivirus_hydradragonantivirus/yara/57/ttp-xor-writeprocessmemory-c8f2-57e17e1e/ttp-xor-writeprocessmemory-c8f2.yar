rule TTP_XOR_WriteProcessMemory_c8f2 {
  strings:
    $key_c8f2 = { 9f 80 [2] ad a2 [2] ab 97 [2] 85 97 [2] ba 8b }

  condition:
    any of them
}