rule TTP_XOR_WriteProcessMemory_c8e9 {
  strings:
    $key_c8e9 = { 9f 9b [2] ad b9 [2] ab 8c [2] 85 8c [2] ba 90 }

  condition:
    any of them
}