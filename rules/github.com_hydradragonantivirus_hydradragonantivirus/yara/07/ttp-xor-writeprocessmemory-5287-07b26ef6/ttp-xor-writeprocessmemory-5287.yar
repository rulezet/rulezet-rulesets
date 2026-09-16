rule TTP_XOR_WriteProcessMemory_5287 {
  strings:
    $key_5287 = { 05 f5 [2] 37 d7 [2] 31 e2 [2] 1f e2 [2] 20 fe }

  condition:
    any of them
}