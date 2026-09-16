rule TTP_XOR_WriteProcessMemory_90ae {
  strings:
    $key_90ae = { c7 dc [2] f5 fe [2] f3 cb [2] dd cb [2] e2 d7 }

  condition:
    any of them
}