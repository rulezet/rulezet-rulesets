rule TTP_XOR_WriteProcessMemory_e4ae {
  strings:
    $key_e4ae = { b3 dc [2] 81 fe [2] 87 cb [2] a9 cb [2] 96 d7 }

  condition:
    any of them
}