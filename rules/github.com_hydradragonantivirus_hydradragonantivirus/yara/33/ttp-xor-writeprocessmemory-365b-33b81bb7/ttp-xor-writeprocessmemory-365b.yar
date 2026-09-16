rule TTP_XOR_WriteProcessMemory_365b {
  strings:
    $key_365b = { 61 29 [2] 53 0b [2] 55 3e [2] 7b 3e [2] 44 22 }

  condition:
    any of them
}