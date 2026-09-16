rule TTP_XOR_WriteProcessMemory_0487 {
  strings:
    $key_0487 = { 53 f5 [2] 61 d7 [2] 67 e2 [2] 49 e2 [2] 76 fe }

  condition:
    any of them
}