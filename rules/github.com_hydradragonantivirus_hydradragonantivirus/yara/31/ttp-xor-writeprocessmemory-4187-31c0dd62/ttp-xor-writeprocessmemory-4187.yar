rule TTP_XOR_WriteProcessMemory_4187 {
  strings:
    $key_4187 = { 16 f5 [2] 24 d7 [2] 22 e2 [2] 0c e2 [2] 33 fe }

  condition:
    any of them
}