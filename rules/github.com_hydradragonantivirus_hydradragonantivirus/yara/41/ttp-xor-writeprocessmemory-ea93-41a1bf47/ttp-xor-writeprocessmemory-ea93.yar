rule TTP_XOR_WriteProcessMemory_ea93 {
  strings:
    $key_ea93 = { bd e1 [2] 8f c3 [2] 89 f6 [2] a7 f6 [2] 98 ea }

  condition:
    any of them
}