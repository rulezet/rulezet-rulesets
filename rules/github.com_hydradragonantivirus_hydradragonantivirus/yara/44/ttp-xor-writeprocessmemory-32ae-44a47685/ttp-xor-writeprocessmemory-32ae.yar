rule TTP_XOR_WriteProcessMemory_32ae {
  strings:
    $key_32ae = { 65 dc [2] 57 fe [2] 51 cb [2] 7f cb [2] 40 d7 }

  condition:
    any of them
}