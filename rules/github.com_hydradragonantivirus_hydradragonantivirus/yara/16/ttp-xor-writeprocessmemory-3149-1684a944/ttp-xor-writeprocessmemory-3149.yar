rule TTP_XOR_WriteProcessMemory_3149 {
  strings:
    $key_3149 = { 66 3b [2] 54 19 [2] 52 2c [2] 7c 2c [2] 43 30 }

  condition:
    any of them
}