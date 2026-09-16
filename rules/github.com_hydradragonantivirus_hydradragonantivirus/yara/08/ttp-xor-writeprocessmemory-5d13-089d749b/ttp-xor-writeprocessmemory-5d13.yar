rule TTP_XOR_WriteProcessMemory_5d13 {
  strings:
    $key_5d13 = { 0a 61 [2] 38 43 [2] 3e 76 [2] 10 76 [2] 2f 6a }

  condition:
    any of them
}