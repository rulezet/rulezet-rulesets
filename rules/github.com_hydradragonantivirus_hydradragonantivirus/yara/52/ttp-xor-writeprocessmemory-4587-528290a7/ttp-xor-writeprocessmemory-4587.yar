rule TTP_XOR_WriteProcessMemory_4587 {
  strings:
    $key_4587 = { 12 f5 [2] 20 d7 [2] 26 e2 [2] 08 e2 [2] 37 fe }

  condition:
    any of them
}