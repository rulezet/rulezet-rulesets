rule TTP_XOR_WriteProcessMemory_1c36 {
  strings:
    $key_1c36 = { 4b 44 [2] 79 66 [2] 7f 53 [2] 51 53 [2] 6e 4f }

  condition:
    any of them
}