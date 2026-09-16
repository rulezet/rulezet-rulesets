rule TTP_XOR_WriteProcessMemory_c49b {
  strings:
    $key_c49b = { 93 e9 [2] a1 cb [2] a7 fe [2] 89 fe [2] b6 e2 }

  condition:
    any of them
}