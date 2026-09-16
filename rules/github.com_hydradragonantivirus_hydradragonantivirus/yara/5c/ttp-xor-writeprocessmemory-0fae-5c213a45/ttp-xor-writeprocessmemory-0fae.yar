rule TTP_XOR_WriteProcessMemory_0fae {
  strings:
    $key_0fae = { 58 dc [2] 6a fe [2] 6c cb [2] 42 cb [2] 7d d7 }

  condition:
    any of them
}