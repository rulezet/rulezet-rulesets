rule TTP_XOR_WriteProcessMemory_ec3b {
  strings:
    $key_ec3b = { bb 49 [2] 89 6b [2] 8f 5e [2] a1 5e [2] 9e 42 }

  condition:
    any of them
}