rule TTP_XOR_WriteProcessMemory_7d67 {
  strings:
    $key_7d67 = { 2a 15 [2] 18 37 [2] 1e 02 [2] 30 02 [2] 0f 1e }

  condition:
    any of them
}