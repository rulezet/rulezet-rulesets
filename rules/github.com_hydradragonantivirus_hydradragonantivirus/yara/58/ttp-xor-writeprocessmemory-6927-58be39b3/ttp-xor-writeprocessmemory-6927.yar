rule TTP_XOR_WriteProcessMemory_6927 {
  strings:
    $key_6927 = { 3e 55 [2] 0c 77 [2] 0a 42 [2] 24 42 [2] 1b 5e }

  condition:
    any of them
}