rule TTP_XOR_WriteProcessMemory_3ca5 {
  strings:
    $key_3ca5 = { 6b d7 [2] 59 f5 [2] 5f c0 [2] 71 c0 [2] 4e dc }

  condition:
    any of them
}