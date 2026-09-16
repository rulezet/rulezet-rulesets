rule TTP_XOR_WriteProcessMemory_8bae {
  strings:
    $key_8bae = { dc dc [2] ee fe [2] e8 cb [2] c6 cb [2] f9 d7 }

  condition:
    any of them
}