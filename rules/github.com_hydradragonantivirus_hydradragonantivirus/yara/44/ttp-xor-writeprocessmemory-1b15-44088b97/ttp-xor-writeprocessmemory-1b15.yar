rule TTP_XOR_WriteProcessMemory_1b15 {
  strings:
    $key_1b15 = { 4c 67 [2] 7e 45 [2] 78 70 [2] 56 70 [2] 69 6c }

  condition:
    any of them
}