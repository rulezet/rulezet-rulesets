rule TTP_XOR_WriteProcessMemory_5435 {
  strings:
    $key_5435 = { 03 47 [2] 31 65 [2] 37 50 [2] 19 50 [2] 26 4c }

  condition:
    any of them
}