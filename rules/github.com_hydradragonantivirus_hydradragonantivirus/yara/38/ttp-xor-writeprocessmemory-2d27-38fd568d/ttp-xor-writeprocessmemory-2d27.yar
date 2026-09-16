rule TTP_XOR_WriteProcessMemory_2d27 {
  strings:
    $key_2d27 = { 7a 55 [2] 48 77 [2] 4e 42 [2] 60 42 [2] 5f 5e }

  condition:
    any of them
}