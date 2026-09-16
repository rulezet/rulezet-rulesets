rule TTP_XOR_WriteProcessMemory_6ca5 {
  strings:
    $key_6ca5 = { 3b d7 [2] 09 f5 [2] 0f c0 [2] 21 c0 [2] 1e dc }

  condition:
    any of them
}