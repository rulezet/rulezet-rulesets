rule TTP_XOR_WriteProcessMemory_e625 {
  strings:
    $key_e625 = { b1 57 [2] 83 75 [2] 85 40 [2] ab 40 [2] 94 5c }

  condition:
    any of them
}