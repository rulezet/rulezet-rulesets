rule TTP_XOR_WriteProcessMemory_c927 {
  strings:
    $key_c927 = { 9e 55 [2] ac 77 [2] aa 42 [2] 84 42 [2] bb 5e }

  condition:
    any of them
}