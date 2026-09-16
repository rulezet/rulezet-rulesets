rule TTP_XOR_WriteProcessMemory_50ae {
  strings:
    $key_50ae = { 07 dc [2] 35 fe [2] 33 cb [2] 1d cb [2] 22 d7 }

  condition:
    any of them
}