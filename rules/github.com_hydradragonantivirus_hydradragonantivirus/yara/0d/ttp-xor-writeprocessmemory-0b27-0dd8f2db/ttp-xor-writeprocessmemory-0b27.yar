rule TTP_XOR_WriteProcessMemory_0b27 {
  strings:
    $key_0b27 = { 5c 55 [2] 6e 77 [2] 68 42 [2] 46 42 [2] 79 5e }

  condition:
    any of them
}