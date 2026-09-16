rule TTP_XOR_WriteProcessMemory_54ae {
  strings:
    $key_54ae = { 03 dc [2] 31 fe [2] 37 cb [2] 19 cb [2] 26 d7 }

  condition:
    any of them
}