rule TTP_XOR_WriteProcessMemory_17ae {
  strings:
    $key_17ae = { 40 dc [2] 72 fe [2] 74 cb [2] 5a cb [2] 65 d7 }

  condition:
    any of them
}