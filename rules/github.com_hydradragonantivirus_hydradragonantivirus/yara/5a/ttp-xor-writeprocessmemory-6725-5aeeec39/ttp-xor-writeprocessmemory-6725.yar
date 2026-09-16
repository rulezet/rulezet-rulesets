rule TTP_XOR_WriteProcessMemory_6725 {
  strings:
    $key_6725 = { 30 57 [2] 02 75 [2] 04 40 [2] 2a 40 [2] 15 5c }

  condition:
    any of them
}