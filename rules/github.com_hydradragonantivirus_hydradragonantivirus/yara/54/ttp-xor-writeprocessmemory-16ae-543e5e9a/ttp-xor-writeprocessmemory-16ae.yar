rule TTP_XOR_WriteProcessMemory_16ae {
  strings:
    $key_16ae = { 41 dc [2] 73 fe [2] 75 cb [2] 5b cb [2] 64 d7 }

  condition:
    any of them
}