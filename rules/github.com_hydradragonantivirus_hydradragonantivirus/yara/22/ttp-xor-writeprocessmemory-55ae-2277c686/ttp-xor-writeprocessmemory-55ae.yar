rule TTP_XOR_WriteProcessMemory_55ae {
  strings:
    $key_55ae = { 02 dc [2] 30 fe [2] 36 cb [2] 18 cb [2] 27 d7 }

  condition:
    any of them
}