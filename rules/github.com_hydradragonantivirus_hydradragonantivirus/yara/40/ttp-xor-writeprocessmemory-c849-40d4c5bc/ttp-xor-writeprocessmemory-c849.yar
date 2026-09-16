rule TTP_XOR_WriteProcessMemory_c849 {
  strings:
    $key_c849 = { 9f 3b [2] ad 19 [2] ab 2c [2] 85 2c [2] ba 30 }

  condition:
    any of them
}