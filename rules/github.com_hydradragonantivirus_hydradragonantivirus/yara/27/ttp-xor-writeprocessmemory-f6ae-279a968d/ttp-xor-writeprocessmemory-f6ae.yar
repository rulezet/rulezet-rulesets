rule TTP_XOR_WriteProcessMemory_f6ae {
  strings:
    $key_f6ae = { a1 dc [2] 93 fe [2] 95 cb [2] bb cb [2] 84 d7 }

  condition:
    any of them
}