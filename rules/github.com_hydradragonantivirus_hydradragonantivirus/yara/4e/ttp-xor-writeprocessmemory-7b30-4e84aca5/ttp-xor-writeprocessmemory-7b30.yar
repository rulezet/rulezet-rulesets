rule TTP_XOR_WriteProcessMemory_7b30 {
  strings:
    $key_7b30 = { 2c 42 [2] 1e 60 [2] 18 55 [2] 36 55 [2] 09 49 }

  condition:
    any of them
}