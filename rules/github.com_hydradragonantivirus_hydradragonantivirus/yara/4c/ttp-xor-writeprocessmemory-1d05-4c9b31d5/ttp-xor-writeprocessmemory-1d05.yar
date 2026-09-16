rule TTP_XOR_WriteProcessMemory_1d05 {
  strings:
    $key_1d05 = { 4a 77 [2] 78 55 [2] 7e 60 [2] 50 60 [2] 6f 7c }

  condition:
    any of them
}