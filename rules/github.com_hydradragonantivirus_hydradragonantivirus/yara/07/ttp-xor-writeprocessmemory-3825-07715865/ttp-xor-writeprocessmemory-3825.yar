rule TTP_XOR_WriteProcessMemory_3825 {
  strings:
    $key_3825 = { 6f 57 [2] 5d 75 [2] 5b 40 [2] 75 40 [2] 4a 5c }

  condition:
    any of them
}