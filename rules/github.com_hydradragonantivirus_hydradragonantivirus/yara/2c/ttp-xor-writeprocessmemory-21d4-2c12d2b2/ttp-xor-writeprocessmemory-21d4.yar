rule TTP_XOR_WriteProcessMemory_21d4 {
  strings:
    $key_21d4 = { 76 a6 [2] 44 84 [2] 42 b1 [2] 6c b1 [2] 53 ad }

  condition:
    any of them
}