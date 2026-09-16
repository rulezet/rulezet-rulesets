rule TTP_XOR_WriteProcessMemory_1275 {
  strings:
    $key_1275 = { 45 07 [2] 77 25 [2] 71 10 [2] 5f 10 [2] 60 0c }

  condition:
    any of them
}