rule TTP_XOR_WriteProcessMemory_7105 {
  strings:
    $key_7105 = { 26 77 [2] 14 55 [2] 12 60 [2] 3c 60 [2] 03 7c }

  condition:
    any of them
}