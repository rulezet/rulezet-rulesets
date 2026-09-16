rule TTP_XOR_WriteProcessMemory_4318 {
  strings:
    $key_4318 = { 14 6a [2] 26 48 [2] 20 7d [2] 0e 7d [2] 31 61 }

  condition:
    any of them
}