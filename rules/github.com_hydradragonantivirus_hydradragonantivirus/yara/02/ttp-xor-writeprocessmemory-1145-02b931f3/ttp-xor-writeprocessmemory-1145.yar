rule TTP_XOR_WriteProcessMemory_1145 {
  strings:
    $key_1145 = { 46 37 [2] 74 15 [2] 72 20 [2] 5c 20 [2] 63 3c }

  condition:
    any of them
}