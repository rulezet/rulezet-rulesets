rule TTP_XOR_WriteProcessMemory_95ae {
  strings:
    $key_95ae = { c2 dc [2] f0 fe [2] f6 cb [2] d8 cb [2] e7 d7 }

  condition:
    any of them
}