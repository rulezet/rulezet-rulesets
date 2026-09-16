rule TTP_XOR_WriteProcessMemory_1487 {
  strings:
    $key_1487 = { 43 f5 [2] 71 d7 [2] 77 e2 [2] 59 e2 [2] 66 fe }

  condition:
    any of them
}