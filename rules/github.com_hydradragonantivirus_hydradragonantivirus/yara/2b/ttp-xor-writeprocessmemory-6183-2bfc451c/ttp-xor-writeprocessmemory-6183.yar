rule TTP_XOR_WriteProcessMemory_6183 {
  strings:
    $key_6183 = { 36 f1 [2] 04 d3 [2] 02 e6 [2] 2c e6 [2] 13 fa }

  condition:
    any of them
}