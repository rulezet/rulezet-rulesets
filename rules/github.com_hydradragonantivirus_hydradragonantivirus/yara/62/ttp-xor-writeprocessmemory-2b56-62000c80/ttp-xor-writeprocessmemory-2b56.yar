rule TTP_XOR_WriteProcessMemory_2b56 {
  strings:
    $key_2b56 = { 7c 24 [2] 4e 06 [2] 48 33 [2] 66 33 [2] 59 2f }

  condition:
    any of them
}