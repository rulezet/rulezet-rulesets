rule TTP_XOR_WriteProcessMemory_2c26 {
  strings:
    $key_2c26 = { 7b 54 [2] 49 76 [2] 4f 43 [2] 61 43 [2] 5e 5f }

  condition:
    any of them
}