rule TTP_XOR_WriteProcessMemory_1109 {
  strings:
    $key_1109 = { 46 7b [2] 74 59 [2] 72 6c [2] 5c 6c [2] 63 70 }

  condition:
    any of them
}