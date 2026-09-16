rule TTP_XOR_WriteProcessMemory_7235 {
  strings:
    $key_7235 = { 25 47 [2] 17 65 [2] 11 50 [2] 3f 50 [2] 00 4c }

  condition:
    any of them
}