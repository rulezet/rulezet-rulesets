rule TTP_XOR_WriteProcessMemory_2c36 {
  strings:
    $key_2c36 = { 7b 44 [2] 49 66 [2] 4f 53 [2] 61 53 [2] 5e 4f }

  condition:
    any of them
}