rule TTP_XOR_WriteProcessMemory_2727 {
  strings:
    $key_2727 = { 70 55 [2] 42 77 [2] 44 42 [2] 6a 42 [2] 55 5e }

  condition:
    any of them
}