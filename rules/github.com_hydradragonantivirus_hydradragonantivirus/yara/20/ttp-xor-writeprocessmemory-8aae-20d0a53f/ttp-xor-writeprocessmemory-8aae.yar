rule TTP_XOR_WriteProcessMemory_8aae {
  strings:
    $key_8aae = { dd dc [2] ef fe [2] e9 cb [2] c7 cb [2] f8 d7 }

  condition:
    any of them
}