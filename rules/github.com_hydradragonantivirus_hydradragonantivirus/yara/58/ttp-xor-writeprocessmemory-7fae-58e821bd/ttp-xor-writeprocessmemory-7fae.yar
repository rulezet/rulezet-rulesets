rule TTP_XOR_WriteProcessMemory_7fae {
  strings:
    $key_7fae = { 28 dc [2] 1a fe [2] 1c cb [2] 32 cb [2] 0d d7 }

  condition:
    any of them
}