rule TTP_XOR_WriteProcessMemory_b7ae {
  strings:
    $key_b7ae = { e0 dc [2] d2 fe [2] d4 cb [2] fa cb [2] c5 d7 }

  condition:
    any of them
}