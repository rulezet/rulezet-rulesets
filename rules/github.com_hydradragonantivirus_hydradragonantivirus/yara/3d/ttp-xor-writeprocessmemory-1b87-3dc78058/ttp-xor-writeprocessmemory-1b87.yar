rule TTP_XOR_WriteProcessMemory_1b87 {
  strings:
    $key_1b87 = { 4c f5 [2] 7e d7 [2] 78 e2 [2] 56 e2 [2] 69 fe }

  condition:
    any of them
}