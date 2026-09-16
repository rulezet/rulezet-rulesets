rule TTP_XOR_WriteProcessMemory_2e77 {
  strings:
    $key_2e77 = { 79 05 [2] 4b 27 [2] 4d 12 [2] 63 12 [2] 5c 0e }

  condition:
    any of them
}