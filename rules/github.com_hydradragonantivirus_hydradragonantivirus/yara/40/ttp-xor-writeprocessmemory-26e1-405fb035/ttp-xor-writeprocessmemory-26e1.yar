rule TTP_XOR_WriteProcessMemory_26e1 {
  strings:
    $key_26e1 = { 71 93 [2] 43 b1 [2] 45 84 [2] 6b 84 [2] 54 98 }

  condition:
    any of them
}