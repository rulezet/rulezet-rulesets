rule TTP_XOR_WriteProcessMemory_3f27 {
  strings:
    $key_3f27 = { 68 55 [2] 5a 77 [2] 5c 42 [2] 72 42 [2] 4d 5e }

  condition:
    any of them
}