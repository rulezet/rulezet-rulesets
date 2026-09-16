rule TTP_XOR_WriteProcessMemory_1129 {
  strings:
    $key_1129 = { 46 5b [2] 74 79 [2] 72 4c [2] 5c 4c [2] 63 50 }

  condition:
    any of them
}