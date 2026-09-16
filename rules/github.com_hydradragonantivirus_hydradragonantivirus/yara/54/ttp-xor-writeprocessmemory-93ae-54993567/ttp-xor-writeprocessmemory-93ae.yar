rule TTP_XOR_WriteProcessMemory_93ae {
  strings:
    $key_93ae = { c4 dc [2] f6 fe [2] f0 cb [2] de cb [2] e1 d7 }

  condition:
    any of them
}