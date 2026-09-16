rule TTP_XOR_WriteProcessMemory_1225 {
  strings:
    $key_1225 = { 45 57 [2] 77 75 [2] 71 40 [2] 5f 40 [2] 60 5c }

  condition:
    any of them
}