rule TTP_XOR_WriteProcessMemory_11e9 {
  strings:
    $key_11e9 = { 46 9b [2] 74 b9 [2] 72 8c [2] 5c 8c [2] 63 90 }

  condition:
    any of them
}