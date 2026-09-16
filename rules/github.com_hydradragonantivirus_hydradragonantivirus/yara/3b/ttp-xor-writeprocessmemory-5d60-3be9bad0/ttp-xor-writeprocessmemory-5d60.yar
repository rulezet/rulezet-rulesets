rule TTP_XOR_WriteProcessMemory_5d60 {
  strings:
    $key_5d60 = { 0a 12 [2] 38 30 [2] 3e 05 [2] 10 05 [2] 2f 19 }

  condition:
    any of them
}