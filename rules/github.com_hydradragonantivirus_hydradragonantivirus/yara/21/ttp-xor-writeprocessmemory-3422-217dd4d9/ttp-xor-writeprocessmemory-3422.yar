rule TTP_XOR_WriteProcessMemory_3422 {
  strings:
    $key_3422 = { 63 50 [2] 51 72 [2] 57 47 [2] 79 47 [2] 46 5b }

  condition:
    any of them
}