rule TTP_XOR_WriteProcessMemory_5225 {
  strings:
    $key_5225 = { 05 57 [2] 37 75 [2] 31 40 [2] 1f 40 [2] 20 5c }

  condition:
    any of them
}