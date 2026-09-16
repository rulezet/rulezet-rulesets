rule TTP_XOR_WriteProcessMemory_0525 {
  strings:
    $key_0525 = { 52 57 [2] 60 75 [2] 66 40 [2] 48 40 [2] 77 5c }

  condition:
    any of them
}