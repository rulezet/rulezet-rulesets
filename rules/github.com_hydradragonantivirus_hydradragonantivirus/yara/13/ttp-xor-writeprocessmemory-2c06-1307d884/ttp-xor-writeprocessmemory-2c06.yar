rule TTP_XOR_WriteProcessMemory_2c06 {
  strings:
    $key_2c06 = { 7b 74 [2] 49 56 [2] 4f 63 [2] 61 63 [2] 5e 7f }

  condition:
    any of them
}