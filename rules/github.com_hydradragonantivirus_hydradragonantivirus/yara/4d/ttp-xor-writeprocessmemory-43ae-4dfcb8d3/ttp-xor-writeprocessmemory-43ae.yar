rule TTP_XOR_WriteProcessMemory_43ae {
  strings:
    $key_43ae = { 14 dc [2] 26 fe [2] 20 cb [2] 0e cb [2] 31 d7 }

  condition:
    any of them
}