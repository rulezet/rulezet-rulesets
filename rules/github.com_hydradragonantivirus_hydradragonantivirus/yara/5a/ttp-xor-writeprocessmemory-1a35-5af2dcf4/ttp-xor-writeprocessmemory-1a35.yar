rule TTP_XOR_WriteProcessMemory_1a35 {
  strings:
    $key_1a35 = { 4d 47 [2] 7f 65 [2] 79 50 [2] 57 50 [2] 68 4c }

  condition:
    any of them
}