rule TTP_XOR_WriteProcessMemory_2df2 {
  strings:
    $key_2df2 = { 7a 80 [2] 48 a2 [2] 4e 97 [2] 60 97 [2] 5f 8b }

  condition:
    any of them
}