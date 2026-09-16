rule TTP_XOR_WriteProcessMemory_4bcd {
  strings:
    $key_4bcd = { 1c bf [2] 2e 9d [2] 28 a8 [2] 06 a8 [2] 39 b4 }

  condition:
    any of them
}