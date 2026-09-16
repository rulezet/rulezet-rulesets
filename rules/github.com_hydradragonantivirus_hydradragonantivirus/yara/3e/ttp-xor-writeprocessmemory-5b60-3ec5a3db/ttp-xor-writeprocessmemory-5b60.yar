rule TTP_XOR_WriteProcessMemory_5b60 {
  strings:
    $key_5b60 = { 0c 12 [2] 3e 30 [2] 38 05 [2] 16 05 [2] 29 19 }

  condition:
    any of them
}