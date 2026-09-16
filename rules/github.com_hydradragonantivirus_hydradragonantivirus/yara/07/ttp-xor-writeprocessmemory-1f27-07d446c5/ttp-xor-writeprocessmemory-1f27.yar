rule TTP_XOR_WriteProcessMemory_1f27 {
  strings:
    $key_1f27 = { 48 55 [2] 7a 77 [2] 7c 42 [2] 52 42 [2] 6d 5e }

  condition:
    any of them
}