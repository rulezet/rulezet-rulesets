rule TTP_XOR_WriteProcessMemory_2106 {
  strings:
    $key_2106 = { 76 74 [2] 44 56 [2] 42 63 [2] 6c 63 [2] 53 7f }

  condition:
    any of them
}