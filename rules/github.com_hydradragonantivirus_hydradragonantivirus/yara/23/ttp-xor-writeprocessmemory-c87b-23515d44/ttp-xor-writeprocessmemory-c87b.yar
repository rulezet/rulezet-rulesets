rule TTP_XOR_WriteProcessMemory_c87b {
  strings:
    $key_c87b = { 9f 09 [2] ad 2b [2] ab 1e [2] 85 1e [2] ba 02 }

  condition:
    any of them
}