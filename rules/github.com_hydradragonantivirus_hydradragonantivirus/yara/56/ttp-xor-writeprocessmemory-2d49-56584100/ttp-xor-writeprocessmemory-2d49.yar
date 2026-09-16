rule TTP_XOR_WriteProcessMemory_2d49 {
  strings:
    $key_2d49 = { 7a 3b [2] 48 19 [2] 4e 2c [2] 60 2c [2] 5f 30 }

  condition:
    any of them
}