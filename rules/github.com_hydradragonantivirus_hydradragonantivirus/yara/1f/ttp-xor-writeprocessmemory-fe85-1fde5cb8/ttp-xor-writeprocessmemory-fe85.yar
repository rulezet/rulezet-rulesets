rule TTP_XOR_WriteProcessMemory_fe85 {
  strings:
    $key_fe85 = { a9 f7 [2] 9b d5 [2] 9d e0 [2] b3 e0 [2] 8c fc }

  condition:
    any of them
}