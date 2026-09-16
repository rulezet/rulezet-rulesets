rule TTP_XOR_WriteProcessMemory_7b29 {
  strings:
    $key_7b29 = { 2c 5b [2] 1e 79 [2] 18 4c [2] 36 4c [2] 09 50 }

  condition:
    any of them
}