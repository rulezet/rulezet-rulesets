rule TTP_XOR_WriteProcessMemory_2287 {
  strings:
    $key_2287 = { 75 f5 [2] 47 d7 [2] 41 e2 [2] 6f e2 [2] 50 fe }

  condition:
    any of them
}