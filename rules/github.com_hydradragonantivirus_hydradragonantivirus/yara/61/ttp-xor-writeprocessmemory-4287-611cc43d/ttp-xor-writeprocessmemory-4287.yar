rule TTP_XOR_WriteProcessMemory_4287 {
  strings:
    $key_4287 = { 15 f5 [2] 27 d7 [2] 21 e2 [2] 0f e2 [2] 30 fe }

  condition:
    any of them
}