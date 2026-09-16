rule TTP_XOR_WriteProcessMemory_c859 {
  strings:
    $key_c859 = { 9f 2b [2] ad 09 [2] ab 3c [2] 85 3c [2] ba 20 }

  condition:
    any of them
}