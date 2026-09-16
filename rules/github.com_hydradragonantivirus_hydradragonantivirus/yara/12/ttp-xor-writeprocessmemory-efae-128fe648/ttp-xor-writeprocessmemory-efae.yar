rule TTP_XOR_WriteProcessMemory_efae {
  strings:
    $key_efae = { b8 dc [2] 8a fe [2] 8c cb [2] a2 cb [2] 9d d7 }

  condition:
    any of them
}