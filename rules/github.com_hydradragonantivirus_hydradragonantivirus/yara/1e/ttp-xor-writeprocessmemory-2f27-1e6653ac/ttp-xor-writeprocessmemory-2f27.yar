rule TTP_XOR_WriteProcessMemory_2f27 {
  strings:
    $key_2f27 = { 78 55 [2] 4a 77 [2] 4c 42 [2] 62 42 [2] 5d 5e }

  condition:
    any of them
}