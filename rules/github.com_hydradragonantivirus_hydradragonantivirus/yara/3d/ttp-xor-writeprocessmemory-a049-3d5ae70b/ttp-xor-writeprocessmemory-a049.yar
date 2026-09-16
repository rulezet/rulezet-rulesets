rule TTP_XOR_WriteProcessMemory_a049 {
  strings:
    $key_a049 = { f7 3b [2] c5 19 [2] c3 2c [2] ed 2c [2] d2 30 }

  condition:
    any of them
}