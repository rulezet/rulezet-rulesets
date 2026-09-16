rule TTP_XOR_WriteProcessMemory_c86b {
  strings:
    $key_c86b = { 9f 19 [2] ad 3b [2] ab 0e [2] 85 0e [2] ba 12 }

  condition:
    any of them
}