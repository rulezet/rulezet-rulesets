rule TTP_XOR_WriteProcessMemory_ffae {
  strings:
    $key_ffae = { a8 dc [2] 9a fe [2] 9c cb [2] b2 cb [2] 8d d7 }

  condition:
    any of them
}