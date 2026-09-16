rule TTP_XOR_WriteProcessMemory_5d05 {
  strings:
    $key_5d05 = { 0a 77 [2] 38 55 [2] 3e 60 [2] 10 60 [2] 2f 7c }

  condition:
    any of them
}