rule TTP_XOR_WriteProcessMemory_3505 {
  strings:
    $key_3505 = { 62 77 [2] 50 55 [2] 56 60 [2] 78 60 [2] 47 7c }

  condition:
    any of them
}