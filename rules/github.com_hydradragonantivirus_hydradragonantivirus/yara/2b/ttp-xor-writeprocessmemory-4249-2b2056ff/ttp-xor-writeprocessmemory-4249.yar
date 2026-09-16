rule TTP_XOR_WriteProcessMemory_4249 {
  strings:
    $key_4249 = { 15 3b [2] 27 19 [2] 21 2c [2] 0f 2c [2] 30 30 }

  condition:
    any of them
}