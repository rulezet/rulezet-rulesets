rule TTP_XOR_WriteProcessMemory_5185 {
  strings:
    $key_5185 = { 06 f7 [2] 34 d5 [2] 32 e0 [2] 1c e0 [2] 23 fc }

  condition:
    any of them
}