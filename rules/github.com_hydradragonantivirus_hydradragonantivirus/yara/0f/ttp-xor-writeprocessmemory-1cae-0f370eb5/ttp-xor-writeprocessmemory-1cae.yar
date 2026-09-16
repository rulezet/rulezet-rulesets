rule TTP_XOR_WriteProcessMemory_1cae {
  strings:
    $key_1cae = { 4b dc [2] 79 fe [2] 7f cb [2] 51 cb [2] 6e d7 }

  condition:
    any of them
}