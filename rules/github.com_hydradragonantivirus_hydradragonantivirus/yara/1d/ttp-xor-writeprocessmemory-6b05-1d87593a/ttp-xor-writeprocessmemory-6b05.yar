rule TTP_XOR_WriteProcessMemory_6b05 {
  strings:
    $key_6b05 = { 3c 77 [2] 0e 55 [2] 08 60 [2] 26 60 [2] 19 7c }

  condition:
    any of them
}