rule TTP_XOR_WriteProcessMemory_20ae {
  strings:
    $key_20ae = { 77 dc [2] 45 fe [2] 43 cb [2] 6d cb [2] 52 d7 }

  condition:
    any of them
}