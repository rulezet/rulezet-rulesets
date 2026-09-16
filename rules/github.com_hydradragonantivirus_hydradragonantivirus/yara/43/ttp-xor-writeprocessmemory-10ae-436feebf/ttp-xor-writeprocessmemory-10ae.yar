rule TTP_XOR_WriteProcessMemory_10ae {
  strings:
    $key_10ae = { 47 dc [2] 75 fe [2] 73 cb [2] 5d cb [2] 62 d7 }

  condition:
    any of them
}