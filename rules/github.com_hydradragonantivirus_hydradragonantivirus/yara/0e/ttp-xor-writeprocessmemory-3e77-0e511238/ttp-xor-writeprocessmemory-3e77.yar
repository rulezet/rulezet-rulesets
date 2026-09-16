rule TTP_XOR_WriteProcessMemory_3e77 {
  strings:
    $key_3e77 = { 69 05 [2] 5b 27 [2] 5d 12 [2] 73 12 [2] 4c 0e }

  condition:
    any of them
}