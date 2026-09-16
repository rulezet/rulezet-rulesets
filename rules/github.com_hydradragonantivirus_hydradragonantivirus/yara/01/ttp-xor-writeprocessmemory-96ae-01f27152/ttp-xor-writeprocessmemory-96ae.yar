rule TTP_XOR_WriteProcessMemory_96ae {
  strings:
    $key_96ae = { c1 dc [2] f3 fe [2] f5 cb [2] db cb [2] e4 d7 }

  condition:
    any of them
}