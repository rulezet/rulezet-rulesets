rule TTP_XOR_WriteProcessMemory_ec0b {
  strings:
    $key_ec0b = { bb 79 [2] 89 5b [2] 8f 6e [2] a1 6e [2] 9e 72 }

  condition:
    any of them
}