rule TTP_XOR_WriteProcessMemory_5c05 {
  strings:
    $key_5c05 = { 0b 77 [2] 39 55 [2] 3f 60 [2] 11 60 [2] 2e 7c }

  condition:
    any of them
}