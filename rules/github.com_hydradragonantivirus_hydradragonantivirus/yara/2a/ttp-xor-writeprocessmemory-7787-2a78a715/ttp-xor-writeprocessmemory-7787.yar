rule TTP_XOR_WriteProcessMemory_7787 {
  strings:
    $key_7787 = { 20 f5 [2] 12 d7 [2] 14 e2 [2] 3a e2 [2] 05 fe }

  condition:
    any of them
}