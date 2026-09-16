rule TTP_XOR_WriteProcessMemory_7205 {
  strings:
    $key_7205 = { 25 77 [2] 17 55 [2] 11 60 [2] 3f 60 [2] 00 7c }

  condition:
    any of them
}