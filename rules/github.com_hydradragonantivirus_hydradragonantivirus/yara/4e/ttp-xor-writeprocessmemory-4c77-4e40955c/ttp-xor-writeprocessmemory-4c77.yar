rule TTP_XOR_WriteProcessMemory_4c77 {
  strings:
    $key_4c77 = { 1b 05 [2] 29 27 [2] 2f 12 [2] 01 12 [2] 3e 0e }

  condition:
    any of them
}