rule TTP_XOR_WriteProcessMemory_1a87 {
  strings:
    $key_1a87 = { 4d f5 [2] 7f d7 [2] 79 e2 [2] 57 e2 [2] 68 fe }

  condition:
    any of them
}