rule TTP_XOR_WriteProcessMemory_0c56 {
  strings:
    $key_0c56 = { 5b 24 [2] 69 06 [2] 6f 33 [2] 41 33 [2] 7e 2f }

  condition:
    any of them
}