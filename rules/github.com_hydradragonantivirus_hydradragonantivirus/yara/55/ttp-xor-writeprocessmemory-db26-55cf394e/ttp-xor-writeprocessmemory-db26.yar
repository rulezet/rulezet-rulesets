rule TTP_XOR_WriteProcessMemory_db26 {
  strings:
    $key_db26 = { 8c 54 [2] be 76 [2] b8 43 [2] 96 43 [2] a9 5f }

  condition:
    any of them
}