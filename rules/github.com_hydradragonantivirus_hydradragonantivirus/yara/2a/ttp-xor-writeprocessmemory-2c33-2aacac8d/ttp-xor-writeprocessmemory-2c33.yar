rule TTP_XOR_WriteProcessMemory_2c33 {
  strings:
    $key_2c33 = { 7b 41 [2] 49 63 [2] 4f 56 [2] 61 56 [2] 5e 4a }

  condition:
    any of them
}