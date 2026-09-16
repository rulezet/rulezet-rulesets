rule TTP_XOR_WriteProcessMemory_1245 {
  strings:
    $key_1245 = { 45 37 [2] 77 15 [2] 71 20 [2] 5f 20 [2] 60 3c }

  condition:
    any of them
}