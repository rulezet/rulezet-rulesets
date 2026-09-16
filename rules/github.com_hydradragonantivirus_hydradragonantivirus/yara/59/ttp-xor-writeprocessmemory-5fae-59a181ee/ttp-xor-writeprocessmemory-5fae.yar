rule TTP_XOR_WriteProcessMemory_5fae {
  strings:
    $key_5fae = { 08 dc [2] 3a fe [2] 3c cb [2] 12 cb [2] 2d d7 }

  condition:
    any of them
}