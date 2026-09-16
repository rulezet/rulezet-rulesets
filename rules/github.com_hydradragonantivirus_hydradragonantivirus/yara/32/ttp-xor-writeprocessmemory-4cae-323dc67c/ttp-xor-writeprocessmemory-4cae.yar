rule TTP_XOR_WriteProcessMemory_4cae {
  strings:
    $key_4cae = { 1b dc [2] 29 fe [2] 2f cb [2] 01 cb [2] 3e d7 }

  condition:
    any of them
}