rule TTP_XOR_WriteProcessMemory_fe87 {
  strings:
    $key_fe87 = { a9 f5 [2] 9b d7 [2] 9d e2 [2] b3 e2 [2] 8c fe }

  condition:
    any of them
}