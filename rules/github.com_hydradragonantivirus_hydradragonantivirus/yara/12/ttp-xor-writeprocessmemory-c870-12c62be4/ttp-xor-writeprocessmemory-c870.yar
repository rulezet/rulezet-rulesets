rule TTP_XOR_WriteProcessMemory_c870 {
  strings:
    $key_c870 = { 9f 02 [2] ad 20 [2] ab 15 [2] 85 15 [2] ba 09 }

  condition:
    any of them
}