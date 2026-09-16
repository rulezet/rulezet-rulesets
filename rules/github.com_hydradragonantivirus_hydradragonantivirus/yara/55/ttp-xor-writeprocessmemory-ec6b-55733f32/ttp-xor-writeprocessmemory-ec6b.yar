rule TTP_XOR_WriteProcessMemory_ec6b {
  strings:
    $key_ec6b = { bb 19 [2] 89 3b [2] 8f 0e [2] a1 0e [2] 9e 12 }

  condition:
    any of them
}