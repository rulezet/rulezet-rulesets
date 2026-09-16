rule TTP_XOR_WriteProcessMemory_0587 {
  strings:
    $key_0587 = { 52 f5 [2] 60 d7 [2] 66 e2 [2] 48 e2 [2] 77 fe }

  condition:
    any of them
}