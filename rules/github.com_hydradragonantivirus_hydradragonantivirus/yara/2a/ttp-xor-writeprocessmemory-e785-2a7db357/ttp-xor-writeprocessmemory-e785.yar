rule TTP_XOR_WriteProcessMemory_e785 {
  strings:
    $key_e785 = { b0 f7 [2] 82 d5 [2] 84 e0 [2] aa e0 [2] 95 fc }

  condition:
    any of them
}