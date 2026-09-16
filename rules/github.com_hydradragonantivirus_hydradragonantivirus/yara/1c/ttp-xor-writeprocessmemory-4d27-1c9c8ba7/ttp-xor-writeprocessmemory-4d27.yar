rule TTP_XOR_WriteProcessMemory_4d27 {
  strings:
    $key_4d27 = { 1a 55 [2] 28 77 [2] 2e 42 [2] 00 42 [2] 3f 5e }

  condition:
    any of them
}