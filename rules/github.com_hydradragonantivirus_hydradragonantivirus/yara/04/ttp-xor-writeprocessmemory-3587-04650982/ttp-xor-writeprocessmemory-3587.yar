rule TTP_XOR_WriteProcessMemory_3587 {
  strings:
    $key_3587 = { 62 f5 [2] 50 d7 [2] 56 e2 [2] 78 e2 [2] 47 fe }

  condition:
    any of them
}