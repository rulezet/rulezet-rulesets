rule TTP_XOR_WriteProcessMemory_1d27 {
  strings:
    $key_1d27 = { 4a 55 [2] 78 77 [2] 7e 42 [2] 50 42 [2] 6f 5e }

  condition:
    any of them
}