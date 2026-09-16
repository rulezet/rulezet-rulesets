rule TTP_XOR_WriteProcessMemory_1405 {
  strings:
    $key_1405 = { 43 77 [2] 71 55 [2] 77 60 [2] 59 60 [2] 66 7c }

  condition:
    any of them
}