rule TTP_XOR_WriteProcessMemory_2d40 {
  strings:
    $key_2d40 = { 7a 32 [2] 48 10 [2] 4e 25 [2] 60 25 [2] 5f 39 }

  condition:
    any of them
}