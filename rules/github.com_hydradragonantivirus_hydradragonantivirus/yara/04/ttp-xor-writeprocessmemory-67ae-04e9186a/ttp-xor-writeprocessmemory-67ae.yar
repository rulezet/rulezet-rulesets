rule TTP_XOR_WriteProcessMemory_67ae {
  strings:
    $key_67ae = { 30 dc [2] 02 fe [2] 04 cb [2] 2a cb [2] 15 d7 }

  condition:
    any of them
}