rule TTP_XOR_WriteProcessMemory_1119 {
  strings:
    $key_1119 = { 46 6b [2] 74 49 [2] 72 7c [2] 5c 7c [2] 63 60 }

  condition:
    any of them
}