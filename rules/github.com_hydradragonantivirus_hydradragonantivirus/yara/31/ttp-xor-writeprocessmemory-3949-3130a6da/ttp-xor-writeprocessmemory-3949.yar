rule TTP_XOR_WriteProcessMemory_3949 {
  strings:
    $key_3949 = { 6e 3b [2] 5c 19 [2] 5a 2c [2] 74 2c [2] 4b 30 }

  condition:
    any of them
}