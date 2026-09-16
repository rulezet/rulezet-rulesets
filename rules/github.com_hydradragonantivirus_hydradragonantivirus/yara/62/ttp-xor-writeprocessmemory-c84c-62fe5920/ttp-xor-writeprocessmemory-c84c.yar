rule TTP_XOR_WriteProcessMemory_c84c {
  strings:
    $key_c84c = { 9f 3e [2] ad 1c [2] ab 29 [2] 85 29 [2] ba 35 }

  condition:
    any of them
}