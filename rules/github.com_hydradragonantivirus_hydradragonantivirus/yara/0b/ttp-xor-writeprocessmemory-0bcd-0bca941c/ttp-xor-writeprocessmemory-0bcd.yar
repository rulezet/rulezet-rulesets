rule TTP_XOR_WriteProcessMemory_0bcd {
  strings:
    $key_0bcd = { 5c bf [2] 6e 9d [2] 68 a8 [2] 46 a8 [2] 79 b4 }

  condition:
    any of them
}