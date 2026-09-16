rule TTP_XOR_WriteProcessMemory_6b77 {
  strings:
    $key_6b77 = { 3c 05 [2] 0e 27 [2] 08 12 [2] 26 12 [2] 19 0e }

  condition:
    any of them
}