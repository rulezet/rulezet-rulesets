rule TTP_XOR_WriteProcessMemory_c85b {
  strings:
    $key_c85b = { 9f 29 [2] ad 0b [2] ab 3e [2] 85 3e [2] ba 22 }

  condition:
    any of them
}