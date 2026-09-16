rule TTP_XOR_WriteProcessMemory_1139 {
  strings:
    $key_1139 = { 46 4b [2] 74 69 [2] 72 5c [2] 5c 5c [2] 63 40 }

  condition:
    any of them
}