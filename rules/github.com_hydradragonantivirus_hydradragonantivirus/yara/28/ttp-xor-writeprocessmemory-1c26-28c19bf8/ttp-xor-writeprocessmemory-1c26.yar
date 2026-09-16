rule TTP_XOR_WriteProcessMemory_1c26 {
  strings:
    $key_1c26 = { 4b 54 [2] 79 76 [2] 7f 43 [2] 51 43 [2] 6e 5f }

  condition:
    any of them
}