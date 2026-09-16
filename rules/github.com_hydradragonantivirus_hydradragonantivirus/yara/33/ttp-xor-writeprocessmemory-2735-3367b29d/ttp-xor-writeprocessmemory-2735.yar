rule TTP_XOR_WriteProcessMemory_2735 {
  strings:
    $key_2735 = { 70 47 [2] 42 65 [2] 44 50 [2] 6a 50 [2] 55 4c }

  condition:
    any of them
}