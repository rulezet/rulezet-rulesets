rule TTP_XOR_WriteProcessMemory_1c27 {
  strings:
    $key_1c27 = { 4b 55 [2] 79 77 [2] 7f 42 [2] 51 42 [2] 6e 5e }

  condition:
    any of them
}