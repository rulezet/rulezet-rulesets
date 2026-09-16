rule TTP_XOR_WriteProcessMemory_5405 {
  strings:
    $key_5405 = { 03 77 [2] 31 55 [2] 37 60 [2] 19 60 [2] 26 7c }

  condition:
    any of them
}