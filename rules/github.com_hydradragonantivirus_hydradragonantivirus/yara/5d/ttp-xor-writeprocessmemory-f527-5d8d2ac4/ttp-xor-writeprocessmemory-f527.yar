rule TTP_XOR_WriteProcessMemory_f527 {
  strings:
    $key_f527 = { a2 55 [2] 90 77 [2] 96 42 [2] b8 42 [2] 87 5e }

  condition:
    any of them
}