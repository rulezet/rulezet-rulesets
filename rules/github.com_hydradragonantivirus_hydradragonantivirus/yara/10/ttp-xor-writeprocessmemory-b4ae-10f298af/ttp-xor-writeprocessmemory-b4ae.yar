rule TTP_XOR_WriteProcessMemory_b4ae {
  strings:
    $key_b4ae = { e3 dc [2] d1 fe [2] d7 cb [2] f9 cb [2] c6 d7 }

  condition:
    any of them
}