rule TTP_XOR_WriteProcessMemory_5275 {
  strings:
    $key_5275 = { 05 07 [2] 37 25 [2] 31 10 [2] 1f 10 [2] 20 0c }

  condition:
    any of them
}