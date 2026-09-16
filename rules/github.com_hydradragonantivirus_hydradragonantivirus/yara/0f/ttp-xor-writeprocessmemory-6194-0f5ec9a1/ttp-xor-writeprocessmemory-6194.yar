rule TTP_XOR_WriteProcessMemory_6194 {
  strings:
    $key_6194 = { 36 e6 [2] 04 c4 [2] 02 f1 [2] 2c f1 [2] 13 ed }

  condition:
    any of them
}