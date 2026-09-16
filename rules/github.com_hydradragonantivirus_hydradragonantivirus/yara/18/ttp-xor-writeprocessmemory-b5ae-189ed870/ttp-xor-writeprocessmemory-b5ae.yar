rule TTP_XOR_WriteProcessMemory_b5ae {
  strings:
    $key_b5ae = { e2 dc [2] d0 fe [2] d6 cb [2] f8 cb [2] c7 d7 }

  condition:
    any of them
}