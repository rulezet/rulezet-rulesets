rule TTP_XOR_WriteProcessMemory_03ae {
  strings:
    $key_03ae = { 54 dc [2] 66 fe [2] 60 cb [2] 4e cb [2] 71 d7 }

  condition:
    any of them
}