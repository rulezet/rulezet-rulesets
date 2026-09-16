rule TTP_XOR_WriteProcessMemory_7c05 {
  strings:
    $key_7c05 = { 2b 77 [2] 19 55 [2] 1f 60 [2] 31 60 [2] 0e 7c }

  condition:
    any of them
}