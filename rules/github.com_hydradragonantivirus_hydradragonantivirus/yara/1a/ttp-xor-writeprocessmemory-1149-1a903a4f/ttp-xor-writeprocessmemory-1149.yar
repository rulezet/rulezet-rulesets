rule TTP_XOR_WriteProcessMemory_1149 {
  strings:
    $key_1149 = { 46 3b [2] 74 19 [2] 72 2c [2] 5c 2c [2] 63 30 }

  condition:
    any of them
}