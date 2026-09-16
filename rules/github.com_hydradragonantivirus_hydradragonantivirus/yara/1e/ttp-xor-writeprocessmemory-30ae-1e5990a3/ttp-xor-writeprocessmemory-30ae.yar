rule TTP_XOR_WriteProcessMemory_30ae {
  strings:
    $key_30ae = { 67 dc [2] 55 fe [2] 53 cb [2] 7d cb [2] 42 d7 }

  condition:
    any of them
}