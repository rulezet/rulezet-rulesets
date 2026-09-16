rule TTP_XOR_WriteProcessMemory_0e27 {
  strings:
    $key_0e27 = { 59 55 [2] 6b 77 [2] 6d 42 [2] 43 42 [2] 7c 5e }

  condition:
    any of them
}