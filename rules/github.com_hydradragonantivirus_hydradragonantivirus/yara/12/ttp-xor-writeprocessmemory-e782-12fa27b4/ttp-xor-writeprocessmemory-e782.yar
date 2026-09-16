rule TTP_XOR_WriteProcessMemory_e782 {
  strings:
    $key_e782 = { b0 f0 [2] 82 d2 [2] 84 e7 [2] aa e7 [2] 95 fb }

  condition:
    any of them
}