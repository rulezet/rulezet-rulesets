rule TTP_XOR_WriteProcessMemory_7840 {
  strings:
    $key_7840 = { 2f 32 [2] 1d 10 [2] 1b 25 [2] 35 25 [2] 0a 39 }

  condition:
    any of them
}