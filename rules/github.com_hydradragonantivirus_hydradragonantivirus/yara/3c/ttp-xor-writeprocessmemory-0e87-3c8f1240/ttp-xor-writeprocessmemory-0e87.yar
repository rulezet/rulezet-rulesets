rule TTP_XOR_WriteProcessMemory_0e87 {
  strings:
    $key_0e87 = { 59 f5 [2] 6b d7 [2] 6d e2 [2] 43 e2 [2] 7c fe }

  condition:
    any of them
}