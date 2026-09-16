rule TTP_XOR_WriteProcessMemory_2732 {
  strings:
    $key_2732 = { 70 40 [2] 42 62 [2] 44 57 [2] 6a 57 [2] 55 4b }

  condition:
    any of them
}