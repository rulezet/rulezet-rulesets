rule TTP_XOR_WriteProcessMemory_2315 {
  strings:
    $key_2315 = { 74 67 [2] 46 45 [2] 40 70 [2] 6e 70 [2] 51 6c }

  condition:
    any of them
}