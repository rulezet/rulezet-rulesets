rule TTP_XOR_WriteProcessMemory_8dae {
  strings:
    $key_8dae = { da dc [2] e8 fe [2] ee cb [2] c0 cb [2] ff d7 }

  condition:
    any of them
}