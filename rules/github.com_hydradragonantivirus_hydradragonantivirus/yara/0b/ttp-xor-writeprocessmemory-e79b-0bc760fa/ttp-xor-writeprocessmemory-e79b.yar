rule TTP_XOR_WriteProcessMemory_e79b {
  strings:
    $key_e79b = { b0 e9 [2] 82 cb [2] 84 fe [2] aa fe [2] 95 e2 }

  condition:
    any of them
}