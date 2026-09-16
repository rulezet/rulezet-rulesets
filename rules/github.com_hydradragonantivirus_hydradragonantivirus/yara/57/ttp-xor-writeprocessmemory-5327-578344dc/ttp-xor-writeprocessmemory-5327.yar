rule TTP_XOR_WriteProcessMemory_5327 {
  strings:
    $key_5327 = { 04 55 [2] 36 77 [2] 30 42 [2] 1e 42 [2] 21 5e }

  condition:
    any of them
}