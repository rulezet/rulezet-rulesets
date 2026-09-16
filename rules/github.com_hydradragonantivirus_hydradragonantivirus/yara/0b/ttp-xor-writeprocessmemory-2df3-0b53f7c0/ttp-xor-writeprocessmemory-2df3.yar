rule TTP_XOR_WriteProcessMemory_2df3 {
  strings:
    $key_2df3 = { 7a 81 [2] 48 a3 [2] 4e 96 [2] 60 96 [2] 5f 8a }

  condition:
    any of them
}