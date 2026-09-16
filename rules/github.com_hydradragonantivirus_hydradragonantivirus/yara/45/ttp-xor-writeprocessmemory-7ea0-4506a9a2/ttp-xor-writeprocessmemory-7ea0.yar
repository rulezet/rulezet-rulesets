rule TTP_XOR_WriteProcessMemory_7ea0 {
  strings:
    $key_7ea0 = { 29 d2 [2] 1b f0 [2] 1d c5 [2] 33 c5 [2] 0c d9 }

  condition:
    any of them
}