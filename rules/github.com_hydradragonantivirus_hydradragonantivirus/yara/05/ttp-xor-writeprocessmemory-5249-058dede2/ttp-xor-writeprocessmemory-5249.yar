rule TTP_XOR_WriteProcessMemory_5249 {
  strings:
    $key_5249 = { 05 3b [2] 37 19 [2] 31 2c [2] 1f 2c [2] 20 30 }

  condition:
    any of them
}