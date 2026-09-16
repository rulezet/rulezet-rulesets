rule TTP_XOR_WriteProcessMemory_1135 {
  strings:
    $key_1135 = { 46 47 [2] 74 65 [2] 72 50 [2] 5c 50 [2] 63 4c }

  condition:
    any of them
}