rule TTP_XOR_WriteProcessMemory_2149 {
  strings:
    $key_2149 = { 76 3b [2] 44 19 [2] 42 2c [2] 6c 2c [2] 53 30 }

  condition:
    any of them
}