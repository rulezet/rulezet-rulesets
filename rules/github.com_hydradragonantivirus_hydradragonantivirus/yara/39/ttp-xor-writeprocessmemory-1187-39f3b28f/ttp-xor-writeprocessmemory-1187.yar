rule TTP_XOR_WriteProcessMemory_1187 {
  strings:
    $key_1187 = { 46 f5 [2] 74 d7 [2] 72 e2 [2] 5c e2 [2] 63 fe }

  condition:
    any of them
}