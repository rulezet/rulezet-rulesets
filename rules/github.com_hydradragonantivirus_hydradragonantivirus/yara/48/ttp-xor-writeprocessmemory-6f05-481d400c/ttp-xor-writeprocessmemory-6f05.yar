rule TTP_XOR_WriteProcessMemory_6f05 {
  strings:
    $key_6f05 = { 38 77 [2] 0a 55 [2] 0c 60 [2] 22 60 [2] 1d 7c }

  condition:
    any of them
}