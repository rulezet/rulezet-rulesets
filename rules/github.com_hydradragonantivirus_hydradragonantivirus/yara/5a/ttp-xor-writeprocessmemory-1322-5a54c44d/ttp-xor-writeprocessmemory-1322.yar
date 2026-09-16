rule TTP_XOR_WriteProcessMemory_1322 {
  strings:
    $key_1322 = { 44 50 [2] 76 72 [2] 70 47 [2] 5e 47 [2] 61 5b }

  condition:
    any of them
}