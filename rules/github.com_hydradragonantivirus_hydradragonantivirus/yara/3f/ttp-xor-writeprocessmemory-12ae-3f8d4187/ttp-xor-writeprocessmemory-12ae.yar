rule TTP_XOR_WriteProcessMemory_12ae {
  strings:
    $key_12ae = { 45 dc [2] 77 fe [2] 71 cb [2] 5f cb [2] 60 d7 }

  condition:
    any of them
}