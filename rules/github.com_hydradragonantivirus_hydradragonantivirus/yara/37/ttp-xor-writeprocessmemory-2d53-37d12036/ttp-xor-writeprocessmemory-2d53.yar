rule TTP_XOR_WriteProcessMemory_2d53 {
  strings:
    $key_2d53 = { 7a 21 [2] 48 03 [2] 4e 36 [2] 60 36 [2] 5f 2a }

  condition:
    any of them
}