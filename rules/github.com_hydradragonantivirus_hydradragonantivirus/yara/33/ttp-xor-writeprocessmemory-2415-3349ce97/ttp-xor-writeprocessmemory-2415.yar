rule TTP_XOR_WriteProcessMemory_2415 {
  strings:
    $key_2415 = { 73 67 [2] 41 45 [2] 47 70 [2] 69 70 [2] 56 6c }

  condition:
    any of them
}