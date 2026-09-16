rule TTP_XOR_WriteProcessMemory_f587 {
  strings:
    $key_f587 = { a2 f5 [2] 90 d7 [2] 96 e2 [2] b8 e2 [2] 87 fe }

  condition:
    any of them
}