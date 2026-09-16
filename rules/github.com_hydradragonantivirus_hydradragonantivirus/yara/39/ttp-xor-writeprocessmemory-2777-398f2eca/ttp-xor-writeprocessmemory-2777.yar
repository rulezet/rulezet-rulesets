rule TTP_XOR_WriteProcessMemory_2777 {
  strings:
    $key_2777 = { 70 05 [2] 42 27 [2] 44 12 [2] 6a 12 [2] 55 0e }

  condition:
    any of them
}