rule TTP_XOR_WriteProcessMemory_2b77 {
  strings:
    $key_2b77 = { 7c 05 [2] 4e 27 [2] 48 12 [2] 66 12 [2] 59 0e }

  condition:
    any of them
}