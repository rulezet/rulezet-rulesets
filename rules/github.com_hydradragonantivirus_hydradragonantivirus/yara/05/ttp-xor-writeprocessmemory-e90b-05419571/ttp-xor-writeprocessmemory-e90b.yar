rule TTP_XOR_WriteProcessMemory_e90b {
  strings:
    $key_e90b = { be 79 [2] 8c 5b [2] 8a 6e [2] a4 6e [2] 9b 72 }

  condition:
    any of them
}