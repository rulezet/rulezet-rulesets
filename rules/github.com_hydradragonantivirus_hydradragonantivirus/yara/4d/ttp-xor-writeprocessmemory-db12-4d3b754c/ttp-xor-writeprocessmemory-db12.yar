rule TTP_XOR_WriteProcessMemory_db12 {
  strings:
    $key_db12 = { 8c 60 [2] be 42 [2] b8 77 [2] 96 77 [2] a9 6b }

  condition:
    any of them
}