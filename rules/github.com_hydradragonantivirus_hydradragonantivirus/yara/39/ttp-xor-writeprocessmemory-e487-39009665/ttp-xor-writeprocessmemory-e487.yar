rule TTP_XOR_WriteProcessMemory_e487 {
  strings:
    $key_e487 = { b3 f5 [2] 81 d7 [2] 87 e2 [2] a9 e2 [2] 96 fe }

  condition:
    any of them
}