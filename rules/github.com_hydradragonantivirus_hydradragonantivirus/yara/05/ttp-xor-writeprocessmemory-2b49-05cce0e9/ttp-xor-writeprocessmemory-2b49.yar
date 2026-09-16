rule TTP_XOR_WriteProcessMemory_2b49 {
  strings:
    $key_2b49 = { 7c 3b [2] 4e 19 [2] 48 2c [2] 66 2c [2] 59 30 }

  condition:
    any of them
}