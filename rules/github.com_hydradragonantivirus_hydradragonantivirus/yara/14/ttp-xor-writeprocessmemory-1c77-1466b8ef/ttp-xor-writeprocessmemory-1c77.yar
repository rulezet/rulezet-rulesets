rule TTP_XOR_WriteProcessMemory_1c77 {
  strings:
    $key_1c77 = { 4b 05 [2] 79 27 [2] 7f 12 [2] 51 12 [2] 6e 0e }

  condition:
    any of them
}