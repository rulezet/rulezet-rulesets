rule TTP_XOR_WriteProcessMemory_5d22 {
  strings:
    $key_5d22 = { 0a 50 [2] 38 72 [2] 3e 47 [2] 10 47 [2] 2f 5b }

  condition:
    any of them
}