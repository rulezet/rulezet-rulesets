rule TTP_XOR_WriteProcessMemory_dbe7 {
  strings:
    $key_dbe7 = { 8c 95 [2] be b7 [2] b8 82 [2] 96 82 [2] a9 9e }

  condition:
    any of them
}