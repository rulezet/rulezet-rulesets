rule TTP_XOR_WriteProcessMemory_e69b {
  strings:
    $key_e69b = { b1 e9 [2] 83 cb [2] 85 fe [2] ab fe [2] 94 e2 }

  condition:
    any of them
}