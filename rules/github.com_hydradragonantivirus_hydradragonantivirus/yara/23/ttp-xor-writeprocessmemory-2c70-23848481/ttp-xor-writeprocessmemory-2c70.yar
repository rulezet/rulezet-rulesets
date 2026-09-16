rule TTP_XOR_WriteProcessMemory_2c70 {
  strings:
    $key_2c70 = { 7b 02 [2] 49 20 [2] 4f 15 [2] 61 15 [2] 5e 09 }

  condition:
    any of them
}