rule TTP_XOR_WriteProcessMemory_2192 {
  strings:
    $key_2192 = { 76 e0 [2] 44 c2 [2] 42 f7 [2] 6c f7 [2] 53 eb }

  condition:
    any of them
}