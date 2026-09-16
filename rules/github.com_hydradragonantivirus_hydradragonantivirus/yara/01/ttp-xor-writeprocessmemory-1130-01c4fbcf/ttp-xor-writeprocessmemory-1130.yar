rule TTP_XOR_WriteProcessMemory_1130 {
  strings:
    $key_1130 = { 46 42 [2] 74 60 [2] 72 55 [2] 5c 55 [2] 63 49 }

  condition:
    any of them
}