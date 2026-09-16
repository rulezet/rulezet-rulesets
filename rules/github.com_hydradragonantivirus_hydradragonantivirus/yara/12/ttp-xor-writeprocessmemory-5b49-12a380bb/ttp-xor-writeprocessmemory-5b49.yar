rule TTP_XOR_WriteProcessMemory_5b49 {
  strings:
    $key_5b49 = { 0c 3b [2] 3e 19 [2] 38 2c [2] 16 2c [2] 29 30 }

  condition:
    any of them
}