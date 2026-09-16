rule TTP_XOR_WriteProcessMemory_dc27 {
  strings:
    $key_dc27 = { 8b 55 [2] b9 77 [2] bf 42 [2] 91 42 [2] ae 5e }

  condition:
    any of them
}