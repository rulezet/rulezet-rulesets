rule TTP_XOR_WriteProcessMemory_5d27 {
  strings:
    $key_5d27 = { 0a 55 [2] 38 77 [2] 3e 42 [2] 10 42 [2] 2f 5e }

  condition:
    any of them
}