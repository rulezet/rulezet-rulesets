rule TTP_XOR_WriteProcessMemory_4705 {
  strings:
    $key_4705 = { 10 77 [2] 22 55 [2] 24 60 [2] 0a 60 [2] 35 7c }

  condition:
    any of them
}