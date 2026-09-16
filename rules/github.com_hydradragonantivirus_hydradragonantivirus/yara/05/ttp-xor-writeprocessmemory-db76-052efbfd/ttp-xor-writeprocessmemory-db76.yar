rule TTP_XOR_WriteProcessMemory_db76 {
  strings:
    $key_db76 = { 8c 04 [2] be 26 [2] b8 13 [2] 96 13 [2] a9 0f }

  condition:
    any of them
}