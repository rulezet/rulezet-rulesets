rule TTP_XOR_WriteProcessMemory_cdae {
  strings:
    $key_cdae = { 9a dc [2] a8 fe [2] ae cb [2] 80 cb [2] bf d7 }

  condition:
    any of them
}