rule TTP_XOR_WriteProcessMemory_ea92 {
  strings:
    $key_ea92 = { bd e0 [2] 8f c2 [2] 89 f7 [2] a7 f7 [2] 98 eb }

  condition:
    any of them
}