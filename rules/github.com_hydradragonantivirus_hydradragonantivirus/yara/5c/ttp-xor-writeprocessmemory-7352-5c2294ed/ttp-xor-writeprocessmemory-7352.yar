rule TTP_XOR_WriteProcessMemory_7352 {
  strings:
    $key_7352 = { 24 20 [2] 16 02 [2] 10 37 [2] 3e 37 [2] 01 2b }

  condition:
    any of them
}