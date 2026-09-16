rule TTP_XOR_WriteProcessMemory_db27 {
  strings:
    $key_db27 = { 8c 55 [2] be 77 [2] b8 42 [2] 96 42 [2] a9 5e }

  condition:
    any of them
}