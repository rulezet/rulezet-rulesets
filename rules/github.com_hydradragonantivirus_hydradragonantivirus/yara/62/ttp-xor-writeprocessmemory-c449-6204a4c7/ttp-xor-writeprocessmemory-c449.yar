rule TTP_XOR_WriteProcessMemory_c449 {
  strings:
    $key_c449 = { 93 3b [2] a1 19 [2] a7 2c [2] 89 2c [2] b6 30 }

  condition:
    any of them
}