rule TTP_XOR_WriteProcessMemory_25e5 {
  strings:
    $key_25e5 = { 72 97 [2] 40 b5 [2] 46 80 [2] 68 80 [2] 57 9c }

  condition:
    any of them
}