rule TTP_XOR_WriteProcessMemory_7c02 {
  strings:
    $key_7c02 = { 2b 70 [2] 19 52 [2] 1f 67 [2] 31 67 [2] 0e 7b }

  condition:
    any of them
}