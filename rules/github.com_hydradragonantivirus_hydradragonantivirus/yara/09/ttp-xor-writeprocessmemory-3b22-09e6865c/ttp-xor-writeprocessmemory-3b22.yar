rule TTP_XOR_WriteProcessMemory_3b22 {
  strings:
    $key_3b22 = { 6c 50 [2] 5e 72 [2] 58 47 [2] 76 47 [2] 49 5b }

  condition:
    any of them
}