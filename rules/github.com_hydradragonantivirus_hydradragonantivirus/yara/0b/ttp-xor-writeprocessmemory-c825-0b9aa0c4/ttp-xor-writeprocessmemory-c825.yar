rule TTP_XOR_WriteProcessMemory_c825 {
  strings:
    $key_c825 = { 9f 57 [2] ad 75 [2] ab 40 [2] 85 40 [2] ba 5c }

  condition:
    any of them
}