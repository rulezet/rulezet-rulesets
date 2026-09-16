rule TTP_XOR_WriteProcessMemory_61b3 {
  strings:
    $key_61b3 = { 36 c1 [2] 04 e3 [2] 02 d6 [2] 2c d6 [2] 13 ca }

  condition:
    any of them
}