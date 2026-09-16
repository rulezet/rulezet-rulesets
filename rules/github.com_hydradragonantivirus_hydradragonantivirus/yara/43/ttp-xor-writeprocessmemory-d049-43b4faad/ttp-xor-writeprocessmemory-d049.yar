rule TTP_XOR_WriteProcessMemory_d049 {
  strings:
    $key_d049 = { 87 3b [2] b5 19 [2] b3 2c [2] 9d 2c [2] a2 30 }

  condition:
    any of them
}