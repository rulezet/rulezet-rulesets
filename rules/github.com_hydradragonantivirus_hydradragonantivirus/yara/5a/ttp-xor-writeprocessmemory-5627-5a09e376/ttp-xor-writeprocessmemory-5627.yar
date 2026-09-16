rule TTP_XOR_WriteProcessMemory_5627 {
  strings:
    $key_5627 = { 01 55 [2] 33 77 [2] 35 42 [2] 1b 42 [2] 24 5e }

  condition:
    any of them
}