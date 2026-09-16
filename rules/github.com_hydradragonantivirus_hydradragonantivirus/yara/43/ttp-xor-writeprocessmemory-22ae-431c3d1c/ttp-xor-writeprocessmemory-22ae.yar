rule TTP_XOR_WriteProcessMemory_22ae {
  strings:
    $key_22ae = { 75 dc [2] 47 fe [2] 41 cb [2] 6f cb [2] 50 d7 }

  condition:
    any of them
}