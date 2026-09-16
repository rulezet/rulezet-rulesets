rule TTP_XOR_WriteProcessMemory_5d40 {
  strings:
    $key_5d40 = { 0a 32 [2] 38 10 [2] 3e 25 [2] 10 25 [2] 2f 39 }

  condition:
    any of them
}