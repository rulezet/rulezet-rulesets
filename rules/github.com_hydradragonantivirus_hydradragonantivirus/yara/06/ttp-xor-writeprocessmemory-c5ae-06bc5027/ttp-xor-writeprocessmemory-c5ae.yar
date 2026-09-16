rule TTP_XOR_WriteProcessMemory_c5ae {
  strings:
    $key_c5ae = { 92 dc [2] a0 fe [2] a6 cb [2] 88 cb [2] b7 d7 }

  condition:
    any of them
}