rule TTP_XOR_WriteProcessMemory_5a87 {
  strings:
    $key_5a87 = { 0d f5 [2] 3f d7 [2] 39 e2 [2] 17 e2 [2] 28 fe }

  condition:
    any of them
}