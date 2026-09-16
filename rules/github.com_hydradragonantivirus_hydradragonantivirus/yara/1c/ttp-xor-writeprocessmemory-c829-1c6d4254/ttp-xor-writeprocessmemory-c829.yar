rule TTP_XOR_WriteProcessMemory_c829 {
  strings:
    $key_c829 = { 9f 5b [2] ad 79 [2] ab 4c [2] 85 4c [2] ba 50 }

  condition:
    any of them
}