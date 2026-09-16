rule TTP_XOR_WriteProcessMemory_3bcd {
  strings:
    $key_3bcd = { 6c bf [2] 5e 9d [2] 58 a8 [2] 76 a8 [2] 49 b4 }

  condition:
    any of them
}