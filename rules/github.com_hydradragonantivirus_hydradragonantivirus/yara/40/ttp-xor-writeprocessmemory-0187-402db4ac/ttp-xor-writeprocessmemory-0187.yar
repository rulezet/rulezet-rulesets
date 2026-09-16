rule TTP_XOR_WriteProcessMemory_0187 {
  strings:
    $key_0187 = { 56 f5 [2] 64 d7 [2] 62 e2 [2] 4c e2 [2] 73 fe }

  condition:
    any of them
}