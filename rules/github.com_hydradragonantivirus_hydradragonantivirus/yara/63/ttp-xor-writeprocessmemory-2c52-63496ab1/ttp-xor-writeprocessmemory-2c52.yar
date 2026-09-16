rule TTP_XOR_WriteProcessMemory_2c52 {
  strings:
    $key_2c52 = { 7b 20 [2] 49 02 [2] 4f 37 [2] 61 37 [2] 5e 2b }

  condition:
    any of them
}