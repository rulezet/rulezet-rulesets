rule TTP_XOR_WriteProcessMemory_2e49 {
  strings:
    $key_2e49 = { 79 3b [2] 4b 19 [2] 4d 2c [2] 63 2c [2] 5c 30 }

  condition:
    any of them
}