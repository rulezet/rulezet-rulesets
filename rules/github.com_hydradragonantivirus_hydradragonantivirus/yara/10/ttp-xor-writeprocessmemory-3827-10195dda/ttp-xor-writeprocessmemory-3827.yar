rule TTP_XOR_WriteProcessMemory_3827 {
  strings:
    $key_3827 = { 6f 55 [2] 5d 77 [2] 5b 42 [2] 75 42 [2] 4a 5e }

  condition:
    any of them
}