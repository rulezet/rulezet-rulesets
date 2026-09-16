rule TTP_XOR_WriteProcessMemory_d249 {
  strings:
    $key_d249 = { 85 3b [2] b7 19 [2] b1 2c [2] 9f 2c [2] a0 30 }

  condition:
    any of them
}