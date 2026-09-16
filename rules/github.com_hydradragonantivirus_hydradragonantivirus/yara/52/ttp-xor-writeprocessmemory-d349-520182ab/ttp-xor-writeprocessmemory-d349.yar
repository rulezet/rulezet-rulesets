rule TTP_XOR_WriteProcessMemory_d349 {
  strings:
    $key_d349 = { 84 3b [2] b6 19 [2] b0 2c [2] 9e 2c [2] a1 30 }

  condition:
    any of them
}