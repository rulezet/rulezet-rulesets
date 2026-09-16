rule TTP_XOR_WriteProcessMemory_6422 {
  strings:
    $key_6422 = { 33 50 [2] 01 72 [2] 07 47 [2] 29 47 [2] 16 5b }

  condition:
    any of them
}