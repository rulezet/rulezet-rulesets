rule TTP_XOR_WriteProcessMemory_36c5 {
  strings:
    $key_36c5 = { 61 b7 [2] 53 95 [2] 55 a0 [2] 7b a0 [2] 44 bc }

  condition:
    any of them
}