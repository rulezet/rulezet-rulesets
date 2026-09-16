rule TTP_XOR_WriteProcessMemory_db23 {
  strings:
    $key_db23 = { 8c 51 [2] be 73 [2] b8 46 [2] 96 46 [2] a9 5a }

  condition:
    any of them
}