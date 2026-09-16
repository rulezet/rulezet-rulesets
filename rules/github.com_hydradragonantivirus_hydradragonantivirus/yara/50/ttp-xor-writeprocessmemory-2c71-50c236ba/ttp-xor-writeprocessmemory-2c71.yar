rule TTP_XOR_WriteProcessMemory_2c71 {
  strings:
    $key_2c71 = { 7b 03 [2] 49 21 [2] 4f 14 [2] 61 14 [2] 5e 08 }

  condition:
    any of them
}