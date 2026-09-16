rule TTP_XOR_WriteProcessMemory_c855 {
  strings:
    $key_c855 = { 9f 27 [2] ad 05 [2] ab 30 [2] 85 30 [2] ba 2c }

  condition:
    any of them
}