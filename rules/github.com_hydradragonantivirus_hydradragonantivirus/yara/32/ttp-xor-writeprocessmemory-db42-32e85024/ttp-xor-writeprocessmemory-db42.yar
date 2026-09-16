rule TTP_XOR_WriteProcessMemory_db42 {
  strings:
    $key_db42 = { 8c 30 [2] be 12 [2] b8 27 [2] 96 27 [2] a9 3b }

  condition:
    any of them
}