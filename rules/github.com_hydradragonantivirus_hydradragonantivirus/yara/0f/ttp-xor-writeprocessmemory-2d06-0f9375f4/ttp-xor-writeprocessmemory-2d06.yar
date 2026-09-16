rule TTP_XOR_WriteProcessMemory_2d06 {
  strings:
    $key_2d06 = { 7a 74 [2] 48 56 [2] 4e 63 [2] 60 63 [2] 5f 7f }

  condition:
    any of them
}