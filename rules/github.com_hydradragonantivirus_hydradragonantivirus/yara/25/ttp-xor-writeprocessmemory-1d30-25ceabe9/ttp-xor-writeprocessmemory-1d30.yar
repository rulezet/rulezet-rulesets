rule TTP_XOR_WriteProcessMemory_1d30 {
  strings:
    $key_1d30 = { 4a 42 [2] 78 60 [2] 7e 55 [2] 50 55 [2] 6f 49 }

  condition:
    any of them
}