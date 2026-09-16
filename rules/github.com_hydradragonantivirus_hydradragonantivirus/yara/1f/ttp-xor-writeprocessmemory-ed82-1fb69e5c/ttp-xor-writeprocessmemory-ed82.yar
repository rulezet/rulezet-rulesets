rule TTP_XOR_WriteProcessMemory_ed82 {
  strings:
    $key_ed82 = { ba f0 [2] 88 d2 [2] 8e e7 [2] a0 e7 [2] 9f fb }

  condition:
    any of them
}