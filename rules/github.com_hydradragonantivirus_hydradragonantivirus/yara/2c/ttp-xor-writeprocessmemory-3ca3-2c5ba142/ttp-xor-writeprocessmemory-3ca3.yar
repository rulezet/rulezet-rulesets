rule TTP_XOR_WriteProcessMemory_3ca3 {
  strings:
    $key_3ca3 = { 6b d1 [2] 59 f3 [2] 5f c6 [2] 71 c6 [2] 4e da }

  condition:
    any of them
}