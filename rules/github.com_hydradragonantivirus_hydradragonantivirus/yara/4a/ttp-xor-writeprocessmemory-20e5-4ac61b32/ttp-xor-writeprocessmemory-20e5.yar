rule TTP_XOR_WriteProcessMemory_20e5 {
  strings:
    $key_20e5 = { 77 97 [2] 45 b5 [2] 43 80 [2] 6d 80 [2] 52 9c }

  condition:
    any of them
}