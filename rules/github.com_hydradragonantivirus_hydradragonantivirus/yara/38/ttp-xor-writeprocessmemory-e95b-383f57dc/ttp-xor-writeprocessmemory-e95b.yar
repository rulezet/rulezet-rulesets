rule TTP_XOR_WriteProcessMemory_e95b {
  strings:
    $key_e95b = { be 29 [2] 8c 0b [2] 8a 3e [2] a4 3e [2] 9b 22 }

  condition:
    any of them
}