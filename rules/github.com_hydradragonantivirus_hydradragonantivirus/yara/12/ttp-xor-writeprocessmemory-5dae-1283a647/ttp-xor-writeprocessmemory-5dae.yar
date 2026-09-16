rule TTP_XOR_WriteProcessMemory_5dae {
  strings:
    $key_5dae = { 0a dc [2] 38 fe [2] 3e cb [2] 10 cb [2] 2f d7 }

  condition:
    any of them
}