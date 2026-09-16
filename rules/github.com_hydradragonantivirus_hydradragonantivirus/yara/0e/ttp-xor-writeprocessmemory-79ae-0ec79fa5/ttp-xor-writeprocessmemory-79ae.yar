rule TTP_XOR_WriteProcessMemory_79ae {
  strings:
    $key_79ae = { 2e dc [2] 1c fe [2] 1a cb [2] 34 cb [2] 0b d7 }

  condition:
    any of them
}