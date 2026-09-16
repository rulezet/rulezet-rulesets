rule TTP_XOR_WriteProcessMemory_2552 {
  strings:
    $key_2552 = { 72 20 [2] 40 02 [2] 46 37 [2] 68 37 [2] 57 2b }

  condition:
    any of them
}