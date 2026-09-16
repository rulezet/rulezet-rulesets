rule TTP_XOR_WriteProcessMemory_2cae {
  strings:
    $key_2cae = { 7b dc [2] 49 fe [2] 4f cb [2] 61 cb [2] 5e d7 }

  condition:
    any of them
}