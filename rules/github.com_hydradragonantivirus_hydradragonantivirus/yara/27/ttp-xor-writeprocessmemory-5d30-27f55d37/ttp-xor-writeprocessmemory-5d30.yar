rule TTP_XOR_WriteProcessMemory_5d30 {
  strings:
    $key_5d30 = { 0a 42 [2] 38 60 [2] 3e 55 [2] 10 55 [2] 2f 49 }

  condition:
    any of them
}