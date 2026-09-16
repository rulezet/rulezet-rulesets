rule TTP_XOR_WriteProcessMemory_1bcd {
  strings:
    $key_1bcd = { 4c bf [2] 7e 9d [2] 78 a8 [2] 56 a8 [2] 69 b4 }

  condition:
    any of them
}