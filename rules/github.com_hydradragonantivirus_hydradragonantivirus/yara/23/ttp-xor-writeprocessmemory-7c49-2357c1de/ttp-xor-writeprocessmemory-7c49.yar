rule TTP_XOR_WriteProcessMemory_7c49 {
  strings:
    $key_7c49 = { 2b 3b [2] 19 19 [2] 1f 2c [2] 31 2c [2] 0e 30 }

  condition:
    any of them
}