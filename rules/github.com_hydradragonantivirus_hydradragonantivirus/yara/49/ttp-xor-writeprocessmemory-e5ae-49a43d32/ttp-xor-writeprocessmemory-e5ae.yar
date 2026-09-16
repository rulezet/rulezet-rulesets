rule TTP_XOR_WriteProcessMemory_e5ae {
  strings:
    $key_e5ae = { b2 dc [2] 80 fe [2] 86 cb [2] a8 cb [2] 97 d7 }

  condition:
    any of them
}