rule TTP_XOR_WriteProcessMemory_2dae {
  strings:
    $key_2dae = { 7a dc [2] 48 fe [2] 4e cb [2] 60 cb [2] 5f d7 }

  condition:
    any of them
}