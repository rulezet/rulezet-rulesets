rule TTP_XOR_WriteProcessMemory_db24 {
  strings:
    $key_db24 = { 8c 56 [2] be 74 [2] b8 41 [2] 96 41 [2] a9 5d }

  condition:
    any of them
}