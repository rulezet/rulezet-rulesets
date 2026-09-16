rule TTP_XOR_WriteProcessMemory_7287 {
  strings:
    $key_7287 = { 25 f5 [2] 17 d7 [2] 11 e2 [2] 3f e2 [2] 00 fe }

  condition:
    any of them
}