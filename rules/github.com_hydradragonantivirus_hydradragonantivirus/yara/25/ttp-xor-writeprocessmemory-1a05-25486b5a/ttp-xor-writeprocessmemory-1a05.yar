rule TTP_XOR_WriteProcessMemory_1a05 {
  strings:
    $key_1a05 = { 4d 77 [2] 7f 55 [2] 79 60 [2] 57 60 [2] 68 7c }

  condition:
    any of them
}