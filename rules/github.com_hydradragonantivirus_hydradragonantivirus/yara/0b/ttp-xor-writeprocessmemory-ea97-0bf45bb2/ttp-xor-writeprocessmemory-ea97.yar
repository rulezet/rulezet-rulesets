rule TTP_XOR_WriteProcessMemory_ea97 {
  strings:
    $key_ea97 = { bd e5 [2] 8f c7 [2] 89 f2 [2] a7 f2 [2] 98 ee }

  condition:
    any of them
}