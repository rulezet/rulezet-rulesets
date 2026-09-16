rule TTP_XOR_WriteProcessMemory_14ae {
  strings:
    $key_14ae = { 43 dc [2] 71 fe [2] 77 cb [2] 59 cb [2] 66 d7 }

  condition:
    any of them
}