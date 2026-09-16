rule TTP_XOR_WriteProcessMemory_1305 {
  strings:
    $key_1305 = { 44 77 [2] 76 55 [2] 70 60 [2] 5e 60 [2] 61 7c }

  condition:
    any of them
}