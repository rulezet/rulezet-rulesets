rule TTP_XOR_WriteProcessMemory_3545 {
  strings:
    $key_3545 = { 62 37 [2] 50 15 [2] 56 20 [2] 78 20 [2] 47 3c }

  condition:
    any of them
}