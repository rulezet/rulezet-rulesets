rule TTP_XOR_WriteProcessMemory_e0ae {
  strings:
    $key_e0ae = { b7 dc [2] 85 fe [2] 83 cb [2] ad cb [2] 92 d7 }

  condition:
    any of them
}