rule TTP_XOR_WriteProcessMemory_db53 {
  strings:
    $key_db53 = { 8c 21 [2] be 03 [2] b8 36 [2] 96 36 [2] a9 2a }

  condition:
    any of them
}