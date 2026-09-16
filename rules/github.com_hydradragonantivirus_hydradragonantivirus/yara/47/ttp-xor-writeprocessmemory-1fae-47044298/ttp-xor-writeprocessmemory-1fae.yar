rule TTP_XOR_WriteProcessMemory_1fae {
  strings:
    $key_1fae = { 48 dc [2] 7a fe [2] 7c cb [2] 52 cb [2] 6d d7 }

  condition:
    any of them
}