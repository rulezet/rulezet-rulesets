rule TTP_XOR_WriteProcessMemory_13ae {
  strings:
    $key_13ae = { 44 dc [2] 76 fe [2] 70 cb [2] 5e cb [2] 61 d7 }

  condition:
    any of them
}