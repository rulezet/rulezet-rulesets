rule TTP_XOR_WriteProcessMemory_e449 {
  strings:
    $key_e449 = { b3 3b [2] 81 19 [2] 87 2c [2] a9 2c [2] 96 30 }

  condition:
    any of them
}