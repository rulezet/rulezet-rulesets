rule TTP_XOR_WriteProcessMemory_2a49 {
  strings:
    $key_2a49 = { 7d 3b [2] 4f 19 [2] 49 2c [2] 67 2c [2] 58 30 }

  condition:
    any of them
}