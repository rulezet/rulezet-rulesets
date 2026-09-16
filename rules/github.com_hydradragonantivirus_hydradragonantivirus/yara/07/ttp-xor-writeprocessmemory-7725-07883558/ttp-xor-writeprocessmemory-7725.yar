rule TTP_XOR_WriteProcessMemory_7725 {
  strings:
    $key_7725 = { 20 57 [2] 12 75 [2] 14 40 [2] 3a 40 [2] 05 5c }

  condition:
    any of them
}