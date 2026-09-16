rule TTP_XOR_WriteProcessMemory_d39b {
  strings:
    $key_d39b = { 84 e9 [2] b6 cb [2] b0 fe [2] 9e fe [2] a1 e2 }

  condition:
    any of them
}