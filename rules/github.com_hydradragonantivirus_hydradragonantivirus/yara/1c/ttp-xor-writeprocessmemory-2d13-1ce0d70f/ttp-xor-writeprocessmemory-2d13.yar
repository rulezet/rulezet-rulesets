rule TTP_XOR_WriteProcessMemory_2d13 {
  strings:
    $key_2d13 = { 7a 61 [2] 48 43 [2] 4e 76 [2] 60 76 [2] 5f 6a }

  condition:
    any of them
}