rule TTP_XOR_WriteProcessMemory_7b27 {
  strings:
    $key_7b27 = { 2c 55 [2] 1e 77 [2] 18 42 [2] 36 42 [2] 09 5e }

  condition:
    any of them
}