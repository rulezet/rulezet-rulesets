rule TTP_XOR_WriteProcessMemory_3b05 {
  strings:
    $key_3b05 = { 6c 77 [2] 5e 55 [2] 58 60 [2] 76 60 [2] 49 7c }

  condition:
    any of them
}