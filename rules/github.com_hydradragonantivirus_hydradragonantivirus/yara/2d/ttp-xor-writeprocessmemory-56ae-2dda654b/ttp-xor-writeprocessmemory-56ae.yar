rule TTP_XOR_WriteProcessMemory_56ae {
  strings:
    $key_56ae = { 01 dc [2] 33 fe [2] 35 cb [2] 1b cb [2] 24 d7 }

  condition:
    any of them
}