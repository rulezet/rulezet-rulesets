rule TTP_XOR_WriteProcessMemory_562b {
  strings:
    $key_562b = { 01 59 [2] 33 7b [2] 35 4e [2] 1b 4e [2] 24 52 }

  condition:
    any of them
}