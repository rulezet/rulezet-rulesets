rule TTP_XOR_WriteProcessMemory_83ae {
  strings:
    $key_83ae = { d4 dc [2] e6 fe [2] e0 cb [2] ce cb [2] f1 d7 }

  condition:
    any of them
}