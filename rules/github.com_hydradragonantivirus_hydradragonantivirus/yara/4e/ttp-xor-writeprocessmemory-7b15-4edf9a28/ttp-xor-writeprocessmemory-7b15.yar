rule TTP_XOR_WriteProcessMemory_7b15 {
  strings:
    $key_7b15 = { 2c 67 [2] 1e 45 [2] 18 70 [2] 36 70 [2] 09 6c }

  condition:
    any of them
}