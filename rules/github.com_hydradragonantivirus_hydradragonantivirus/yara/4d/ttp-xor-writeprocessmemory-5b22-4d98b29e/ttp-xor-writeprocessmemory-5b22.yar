rule TTP_XOR_WriteProcessMemory_5b22 {
  strings:
    $key_5b22 = { 0c 50 [2] 3e 72 [2] 38 47 [2] 16 47 [2] 29 5b }

  condition:
    any of them
}