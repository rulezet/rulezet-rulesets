rule TTP_XOR_WriteProcessMemory_6d05 {
  strings:
    $key_6d05 = { 3a 77 [2] 08 55 [2] 0e 60 [2] 20 60 [2] 1f 7c }

  condition:
    any of them
}