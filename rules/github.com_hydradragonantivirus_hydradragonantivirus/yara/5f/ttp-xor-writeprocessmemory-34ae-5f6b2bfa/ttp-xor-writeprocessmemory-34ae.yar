rule TTP_XOR_WriteProcessMemory_34ae {
  strings:
    $key_34ae = { 63 dc [2] 51 fe [2] 57 cb [2] 79 cb [2] 46 d7 }

  condition:
    any of them
}