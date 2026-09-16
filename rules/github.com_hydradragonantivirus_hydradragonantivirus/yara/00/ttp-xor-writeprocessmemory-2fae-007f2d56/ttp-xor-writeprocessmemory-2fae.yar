rule TTP_XOR_WriteProcessMemory_2fae {
  strings:
    $key_2fae = { 78 dc [2] 4a fe [2] 4c cb [2] 62 cb [2] 5d d7 }

  condition:
    any of them
}