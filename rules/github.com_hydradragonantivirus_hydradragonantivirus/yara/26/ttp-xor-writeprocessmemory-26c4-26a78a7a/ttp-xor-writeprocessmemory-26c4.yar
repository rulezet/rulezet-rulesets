rule TTP_XOR_WriteProcessMemory_26c4 {
  strings:
    $key_26c4 = { 71 b6 [2] 43 94 [2] 45 a1 [2] 6b a1 [2] 54 bd }

  condition:
    any of them
}