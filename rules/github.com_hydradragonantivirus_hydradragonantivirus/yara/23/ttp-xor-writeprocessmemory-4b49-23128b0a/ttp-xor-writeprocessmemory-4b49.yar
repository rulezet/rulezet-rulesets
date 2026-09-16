rule TTP_XOR_WriteProcessMemory_4b49 {
  strings:
    $key_4b49 = { 1c 3b [2] 2e 19 [2] 28 2c [2] 06 2c [2] 39 30 }

  condition:
    any of them
}