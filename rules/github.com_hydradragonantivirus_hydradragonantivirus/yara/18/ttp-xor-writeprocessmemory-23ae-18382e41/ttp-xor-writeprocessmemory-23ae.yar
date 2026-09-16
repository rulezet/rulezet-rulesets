rule TTP_XOR_WriteProcessMemory_23ae {
  strings:
    $key_23ae = { 74 dc [2] 46 fe [2] 40 cb [2] 6e cb [2] 51 d7 }

  condition:
    any of them
}