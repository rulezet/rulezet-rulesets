rule TTP_XOR_WriteProcessMemory_5587 {
  strings:
    $key_5587 = { 02 f5 [2] 30 d7 [2] 36 e2 [2] 18 e2 [2] 27 fe }

  condition:
    any of them
}