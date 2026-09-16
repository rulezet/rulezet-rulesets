rule TTP_XOR_WriteProcessMemory_2bcd {
  strings:
    $key_2bcd = { 7c bf [2] 4e 9d [2] 48 a8 [2] 66 a8 [2] 59 b4 }

  condition:
    any of them
}