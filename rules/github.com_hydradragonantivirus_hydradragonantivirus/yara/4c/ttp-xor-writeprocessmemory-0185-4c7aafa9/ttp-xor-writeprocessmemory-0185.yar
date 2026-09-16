rule TTP_XOR_WriteProcessMemory_0185 {
  strings:
    $key_0185 = { 56 f7 [2] 64 d5 [2] 62 e0 [2] 4c e0 [2] 73 fc }

  condition:
    any of them
}