rule TTP_XOR_WriteProcessMemory_42ae {
  strings:
    $key_42ae = { 15 dc [2] 27 fe [2] 21 cb [2] 0f cb [2] 30 d7 }

  condition:
    any of them
}