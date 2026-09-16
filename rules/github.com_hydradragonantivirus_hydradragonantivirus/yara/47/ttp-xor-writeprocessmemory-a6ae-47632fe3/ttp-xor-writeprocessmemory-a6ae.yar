rule TTP_XOR_WriteProcessMemory_a6ae {
  strings:
    $key_a6ae = { f1 dc [2] c3 fe [2] c5 cb [2] eb cb [2] d4 d7 }

  condition:
    any of them
}