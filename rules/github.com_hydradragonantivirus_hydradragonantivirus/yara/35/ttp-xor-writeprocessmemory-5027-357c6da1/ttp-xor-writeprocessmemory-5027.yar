rule TTP_XOR_WriteProcessMemory_5027 {
  strings:
    $key_5027 = { 07 55 [2] 35 77 [2] 33 42 [2] 1d 42 [2] 22 5e }

  condition:
    any of them
}