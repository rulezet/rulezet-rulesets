rule TTP_XOR_WriteProcessMemory_1725 {
  strings:
    $key_1725 = { 40 57 [2] 72 75 [2] 74 40 [2] 5a 40 [2] 65 5c }

  condition:
    any of them
}