rule TTP_XOR_WriteProcessMemory_ecfd {
  strings:
    $key_ecfd = { bb 8f [2] 89 ad [2] 8f 98 [2] a1 98 [2] 9e 84 }

  condition:
    any of them
}