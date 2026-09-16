rule TTP_XOR_WriteProcessMemory_7340 {
  strings:
    $key_7340 = { 24 32 [2] 16 10 [2] 10 25 [2] 3e 25 [2] 01 39 }

  condition:
    any of them
}