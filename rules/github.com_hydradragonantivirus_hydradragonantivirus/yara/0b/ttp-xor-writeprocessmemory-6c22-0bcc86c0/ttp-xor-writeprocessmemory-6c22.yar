rule TTP_XOR_WriteProcessMemory_6c22 {
  strings:
    $key_6c22 = { 3b 50 [2] 09 72 [2] 0f 47 [2] 21 47 [2] 1e 5b }

  condition:
    any of them
}