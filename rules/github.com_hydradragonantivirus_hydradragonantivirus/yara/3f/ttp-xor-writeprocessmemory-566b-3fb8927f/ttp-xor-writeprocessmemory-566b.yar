rule TTP_XOR_WriteProcessMemory_566b {
  strings:
    $key_566b = { 01 19 [2] 33 3b [2] 35 0e [2] 1b 0e [2] 24 12 }

  condition:
    any of them
}