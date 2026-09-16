rule TTP_XOR_WriteProcessMemory_db13 {
  strings:
    $key_db13 = { 8c 61 [2] be 43 [2] b8 76 [2] 96 76 [2] a9 6a }

  condition:
    any of them
}