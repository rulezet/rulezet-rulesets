rule TTP_XOR_WriteProcessMemory_efa6 {
  strings:
    $key_efa6 = { b8 d4 [2] 8a f6 [2] 8c c3 [2] a2 c3 [2] 9d df }

  condition:
    any of them
}