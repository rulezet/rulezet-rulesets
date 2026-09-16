rule TTP_XOR_WriteProcessMemory_0149 {
  strings:
    $key_0149 = { 56 3b [2] 64 19 [2] 62 2c [2] 4c 2c [2] 73 30 }

  condition:
    any of them
}