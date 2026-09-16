rule TTP_XOR_WriteProcessMemory_eca7 {
  strings:
    $key_eca7 = { bb d5 [2] 89 f7 [2] 8f c2 [2] a1 c2 [2] 9e de }

  condition:
    any of them
}