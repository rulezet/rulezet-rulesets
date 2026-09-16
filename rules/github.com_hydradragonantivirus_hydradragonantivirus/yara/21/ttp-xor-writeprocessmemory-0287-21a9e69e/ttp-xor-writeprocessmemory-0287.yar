rule TTP_XOR_WriteProcessMemory_0287 {
  strings:
    $key_0287 = { 55 f5 [2] 67 d7 [2] 61 e2 [2] 4f e2 [2] 70 fe }

  condition:
    any of them
}