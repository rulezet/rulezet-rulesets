rule TTP_XOR_WriteProcessMemory_3b87 {
  strings:
    $key_3b87 = { 6c f5 [2] 5e d7 [2] 58 e2 [2] 76 e2 [2] 49 fe }

  condition:
    any of them
}