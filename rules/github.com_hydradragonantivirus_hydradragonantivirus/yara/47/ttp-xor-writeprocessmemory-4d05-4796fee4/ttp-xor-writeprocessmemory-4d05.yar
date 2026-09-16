rule TTP_XOR_WriteProcessMemory_4d05 {
  strings:
    $key_4d05 = { 1a 77 [2] 28 55 [2] 2e 60 [2] 00 60 [2] 3f 7c }

  condition:
    any of them
}