rule TTP_XOR_WriteProcessMemory_6787 {
  strings:
    $key_6787 = { 30 f5 [2] 02 d7 [2] 04 e2 [2] 2a e2 [2] 15 fe }

  condition:
    any of them
}