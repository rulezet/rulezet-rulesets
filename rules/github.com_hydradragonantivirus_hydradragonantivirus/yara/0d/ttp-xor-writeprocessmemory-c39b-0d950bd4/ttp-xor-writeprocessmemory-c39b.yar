rule TTP_XOR_WriteProcessMemory_c39b {
  strings:
    $key_c39b = { 94 e9 [2] a6 cb [2] a0 fe [2] 8e fe [2] b1 e2 }

  condition:
    any of them
}