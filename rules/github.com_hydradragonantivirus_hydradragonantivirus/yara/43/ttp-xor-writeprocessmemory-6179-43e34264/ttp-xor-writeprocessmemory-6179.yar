rule TTP_XOR_WriteProcessMemory_6179 {
  strings:
    $key_6179 = { 36 0b [2] 04 29 [2] 02 1c [2] 2c 1c [2] 13 00 }

  condition:
    any of them
}