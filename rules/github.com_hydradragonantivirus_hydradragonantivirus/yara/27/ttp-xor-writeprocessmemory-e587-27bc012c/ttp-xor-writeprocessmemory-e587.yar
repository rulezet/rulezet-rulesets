rule TTP_XOR_WriteProcessMemory_e587 {
  strings:
    $key_e587 = { b2 f5 [2] 80 d7 [2] 86 e2 [2] a8 e2 [2] 97 fe }

  condition:
    any of them
}