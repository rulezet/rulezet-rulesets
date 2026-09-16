rule TTP_XOR_WriteProcessMemory_1b77 {
  strings:
    $key_1b77 = { 4c 05 [2] 7e 27 [2] 78 12 [2] 56 12 [2] 69 0e }

  condition:
    any of them
}