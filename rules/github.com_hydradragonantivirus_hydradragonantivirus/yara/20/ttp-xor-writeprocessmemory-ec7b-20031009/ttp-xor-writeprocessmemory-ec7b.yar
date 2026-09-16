rule TTP_XOR_WriteProcessMemory_ec7b {
  strings:
    $key_ec7b = { bb 09 [2] 89 2b [2] 8f 1e [2] a1 1e [2] 9e 02 }

  condition:
    any of them
}