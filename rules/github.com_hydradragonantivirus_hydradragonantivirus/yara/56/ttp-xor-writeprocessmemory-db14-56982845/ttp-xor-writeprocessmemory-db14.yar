rule TTP_XOR_WriteProcessMemory_db14 {
  strings:
    $key_db14 = { 8c 66 [2] be 44 [2] b8 71 [2] 96 71 [2] a9 6d }

  condition:
    any of them
}