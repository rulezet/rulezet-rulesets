rule TTP_XOR_WriteProcessMemory_3415 {
  strings:
    $key_3415 = { 63 67 [2] 51 45 [2] 57 70 [2] 79 70 [2] 46 6c }

  condition:
    any of them
}