rule TTP_XOR_WriteProcessMemory_d660 {
  strings:
    $key_d660 = { 81 12 [2] b3 30 [2] b5 05 [2] 9b 05 [2] a4 19 }

  condition:
    any of them
}