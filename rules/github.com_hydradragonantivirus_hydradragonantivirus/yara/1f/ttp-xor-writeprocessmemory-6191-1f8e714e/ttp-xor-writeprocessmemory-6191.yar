rule TTP_XOR_WriteProcessMemory_6191 {
  strings:
    $key_6191 = { 36 e3 [2] 04 c1 [2] 02 f4 [2] 2c f4 [2] 13 e8 }

  condition:
    any of them
}