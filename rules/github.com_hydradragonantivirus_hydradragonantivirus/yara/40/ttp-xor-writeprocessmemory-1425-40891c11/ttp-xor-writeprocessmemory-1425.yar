rule TTP_XOR_WriteProcessMemory_1425 {
  strings:
    $key_1425 = { 43 57 [2] 71 75 [2] 77 40 [2] 59 40 [2] 66 5c }

  condition:
    any of them
}