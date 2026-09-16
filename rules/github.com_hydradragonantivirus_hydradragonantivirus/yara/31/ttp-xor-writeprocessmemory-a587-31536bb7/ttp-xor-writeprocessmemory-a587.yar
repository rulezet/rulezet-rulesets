rule TTP_XOR_WriteProcessMemory_a587 {
  strings:
    $key_a587 = { f2 f5 [2] c0 d7 [2] c6 e2 [2] e8 e2 [2] d7 fe }

  condition:
    any of them
}