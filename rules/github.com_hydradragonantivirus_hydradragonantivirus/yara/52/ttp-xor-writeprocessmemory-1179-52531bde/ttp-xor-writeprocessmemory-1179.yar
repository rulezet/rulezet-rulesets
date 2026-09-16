rule TTP_XOR_WriteProcessMemory_1179 {
  strings:
    $key_1179 = { 46 0b [2] 74 29 [2] 72 1c [2] 5c 1c [2] 63 00 }

  condition:
    any of them
}