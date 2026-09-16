rule TTP_XOR_WriteProcessMemory_6187 {
  strings:
    $key_6187 = { 36 f5 [2] 04 d7 [2] 02 e2 [2] 2c e2 [2] 13 fe }

  condition:
    any of them
}