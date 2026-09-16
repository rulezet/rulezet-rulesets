rule TTP_XOR_WriteProcessMemory_2692 {
  strings:
    $key_2692 = { 71 e0 [2] 43 c2 [2] 45 f7 [2] 6b f7 [2] 54 eb }

  condition:
    any of them
}