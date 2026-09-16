rule TTP_XOR_WriteProcessMemory_7862 {
  strings:
    $key_7862 = { 2f 10 [2] 1d 32 [2] 1b 07 [2] 35 07 [2] 0a 1b }

  condition:
    any of them
}