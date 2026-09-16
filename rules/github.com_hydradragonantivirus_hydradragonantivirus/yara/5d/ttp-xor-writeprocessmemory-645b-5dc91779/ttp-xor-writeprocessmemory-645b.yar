rule TTP_XOR_WriteProcessMemory_645b {
  strings:
    $key_645b = { 33 29 [2] 01 0b [2] 07 3e [2] 29 3e [2] 16 22 }

  condition:
    any of them
}