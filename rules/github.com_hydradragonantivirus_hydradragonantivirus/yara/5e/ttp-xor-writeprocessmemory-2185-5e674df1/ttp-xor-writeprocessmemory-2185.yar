rule TTP_XOR_WriteProcessMemory_2185 {
  strings:
    $key_2185 = { 76 f7 [2] 44 d5 [2] 42 e0 [2] 6c e0 [2] 53 fc }

  condition:
    any of them
}