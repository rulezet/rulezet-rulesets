rule TTP_XOR_WriteProcessMemory_33ae {
  strings:
    $key_33ae = { 64 dc [2] 56 fe [2] 50 cb [2] 7e cb [2] 41 d7 }

  condition:
    any of them
}