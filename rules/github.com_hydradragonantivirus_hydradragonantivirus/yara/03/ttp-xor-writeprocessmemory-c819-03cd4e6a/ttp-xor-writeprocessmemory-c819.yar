rule TTP_XOR_WriteProcessMemory_c819 {
  strings:
    $key_c819 = { 9f 6b [2] ad 49 [2] ab 7c [2] 85 7c [2] ba 60 }

  condition:
    any of them
}