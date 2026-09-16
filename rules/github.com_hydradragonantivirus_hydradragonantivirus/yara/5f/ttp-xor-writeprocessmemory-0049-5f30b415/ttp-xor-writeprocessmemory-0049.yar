rule TTP_XOR_WriteProcessMemory_0049 {
  strings:
    $key_0049 = { 57 3b [2] 65 19 [2] 63 2c [2] 4d 2c [2] 72 30 }

  condition:
    any of them
}