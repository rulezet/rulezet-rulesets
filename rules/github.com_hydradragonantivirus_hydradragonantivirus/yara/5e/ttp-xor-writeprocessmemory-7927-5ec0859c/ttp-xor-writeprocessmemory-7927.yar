rule TTP_XOR_WriteProcessMemory_7927 {
  strings:
    $key_7927 = { 2e 55 [2] 1c 77 [2] 1a 42 [2] 34 42 [2] 0b 5e }

  condition:
    any of them
}