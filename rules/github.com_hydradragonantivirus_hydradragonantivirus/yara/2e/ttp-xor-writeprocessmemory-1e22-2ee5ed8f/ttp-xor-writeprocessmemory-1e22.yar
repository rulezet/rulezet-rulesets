rule TTP_XOR_WriteProcessMemory_1e22 {
  strings:
    $key_1e22 = { 49 50 [2] 7b 72 [2] 7d 47 [2] 53 47 [2] 6c 5b }

  condition:
    any of them
}