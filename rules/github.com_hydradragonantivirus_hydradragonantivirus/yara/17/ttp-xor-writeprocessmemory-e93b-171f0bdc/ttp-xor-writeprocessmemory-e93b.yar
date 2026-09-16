rule TTP_XOR_WriteProcessMemory_e93b {
  strings:
    $key_e93b = { be 49 [2] 8c 6b [2] 8a 5e [2] a4 5e [2] 9b 42 }

  condition:
    any of them
}