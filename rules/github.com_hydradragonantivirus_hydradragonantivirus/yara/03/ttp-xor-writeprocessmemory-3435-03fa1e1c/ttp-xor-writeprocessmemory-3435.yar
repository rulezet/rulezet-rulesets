rule TTP_XOR_WriteProcessMemory_3435 {
  strings:
    $key_3435 = { 63 47 [2] 51 65 [2] 57 50 [2] 79 50 [2] 46 4c }

  condition:
    any of them
}