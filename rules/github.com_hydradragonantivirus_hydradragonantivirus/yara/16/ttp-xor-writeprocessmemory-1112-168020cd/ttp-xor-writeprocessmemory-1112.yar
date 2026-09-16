rule TTP_XOR_WriteProcessMemory_1112 {
  strings:
    $key_1112 = { 46 60 [2] 74 42 [2] 72 77 [2] 5c 77 [2] 63 6b }

  condition:
    any of them
}